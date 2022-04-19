//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The `launcher` will spawn new processes for each cpu core.
use ahash::AHasher;
use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use bit_vec::BitVec;
use clap::{self, StructOpt};
use core::time::Duration;
use packed_struct::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json;
use std::{
    cmp::min,
    collections::BTreeMap,
    env,
    fs::File,
    hash::Hasher,
    io::Read,
    marker::PhantomData,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use libafl::{
    bolts::{
        current_nanos,
        fs::write_file_atomic,
        launcher::Launcher,
        os::Cores,
        ownedref::OwnedSlice,
        rands::Rand,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::{tuple_list, Merge, Named},
        HasLen,
    },
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    events::{EventConfig, EventFirer},
    executors::{CommandExecutor, DiffExecutor},
    feedbacks::{differential::DiffResult, DiffFeedback, Feedback, FeedbackState},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::Generator,
    generators::RandBytesGenerator,
    inputs::{HasBytesVec, HasTargetBytes, Input},
    monitors::MultiMonitor,
    mutators::{
        scheduled::{havoc_mutations, tokens_mutations, StdScheduledMutator},
        token_mutations::Tokens,
    },
    observers::{ObserversTuple, StdOutObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::StdMutationalStage,
    state::{HasClientPerfMonitor, HasCorpus, HasMetadata, HasRand, StdState},
    Error,
};

/// Parses a millseconds int into a [`Duration`], used for commandline arg parsing
fn timeout_from_millis_str(time: &str) -> Result<Duration, Error> {
    Ok(Duration::from_millis(time.parse()?))
}

#[derive(Debug, StructOpt)]
#[clap(
    name = "NeoDiff LibAFL Differntial Fuzzer",
    about = "A Differential fuzzer for EVM",
    author = "Andrea Fioraldi <andreafioraldi@gmail.com>, Dominik Maier <domenukk@gmail.com>"
)]
struct Opt {
    /*#[clap(
        short,
        long,
        parse(try_from_str = Cores::from_cmdline),
        help = "Spawn a client in each of the provided cores. Broker runs in the 0th core. 'all' to select all available cores. 'none' to run a client without binding to any core. eg: '1,2-4,6' selects the cores 1,2,3,4,6.",
        name = "CORES"
    )]
    cores: Cores,

    #[clap(
        short = 'p',
        long,
        help = "Choose the broker TCP port, default is 1337",
        name = "PORT"
    )]
    broker_port: u16,

    #[clap(
        parse(try_from_str),
        short = 'a',
        long,
        help = "Specify a remote broker",
        name = "REMOTE"
    )]
    remote_broker_addr: Option<SocketAddr>,*/
    #[clap(
        parse(try_from_str),
        short,
        long,
        help = "Set an initial corpus directory",
        name = "INPUT"
    )]
    input: Vec<PathBuf>,

    #[clap(
        short,
        long,
        parse(try_from_str),
        help = "Set the output directory, default is ./out",
        name = "OUTPUT",
        default_value = "./out"
    )]
    output: PathBuf,

    #[clap(
        parse(try_from_str = timeout_from_millis_str),
        short,
        long,
        help = "Set the exeucution timeout in milliseconds, default is 1000",
        name = "TIMEOUT",
        default_value = "1000"
    )]
    timeout: Duration,

    #[clap(
        parse(from_os_str),
        short = 'x',
        long,
        help = "Feed the fuzzer with an user-specified list of tokens (often called \"dictionary\"",
        name = "TOKENS",
        multiple_occurrences = true
    )]
    tokens: Vec<PathBuf>,
}

/// A bytes input is the basic input
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct HexInput {
    /// The raw input bytes
    bytes: Vec<u8>,
}

impl Input for HexInput {
    #[cfg(feature = "std")]
    /// Write this input to the file
    fn to_file<P>(&self, path: P) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        write_file_atomic(path, &self.bytes)
    }

    /// Load the content of this input from a file
    #[cfg(feature = "std")]
    fn from_file<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let mut file = File::open(path)?;
        let mut bytes: Vec<u8> = vec![];
        file.read_to_end(&mut bytes)?;
        Ok(HexInput::new(bytes))
    }

    /// Generate a name for this input
    fn generate_name(&self, _idx: usize) -> String {
        let mut hasher = AHasher::new_with_keys(0, 0);
        hasher.write(self.bytes());
        format!("{:016x}", hasher.finish())
    }
}

impl HasBytesVec for HexInput {
    #[inline]
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[inline]
    fn bytes_mut(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }
}

impl HasTargetBytes for HexInput {
    #[inline]
    fn target_bytes(&self) -> OwnedSlice<u8> {
        let h = hex::encode(&self.bytes).into_bytes();
        OwnedSlice::from(h)
    }
}

impl HasLen for HexInput {
    #[inline]
    fn len(&self) -> usize {
        self.bytes.len()
    }
}

impl HexInput {
    /// Creates a new bytes input using the given bytes
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

const DUMMY_BYTES_MAX: usize = 64;

#[derive(Clone, Debug)]
/// Generates random bytes
pub struct RandHexGenerator<S>
where
    S: HasRand,
{
    max_size: usize,
    phantom: PhantomData<S>,
}

impl<S> Generator<HexInput, S> for RandHexGenerator<S>
where
    S: HasRand,
{
    fn generate(&mut self, state: &mut S) -> Result<HexInput, Error> {
        let mut size = state.rand_mut().below(self.max_size as u64);
        if size == 0 {
            size = 1;
        }
        let random_bytes: Vec<u8> = (0..size)
            .map(|_| state.rand_mut().below(256) as u8)
            .collect();
        Ok(HexInput::new(random_bytes))
    }

    /// Generates up to `DUMMY_BYTES_MAX` non-random dummy bytes (0)
    fn generate_dummy(&self, _state: &mut S) -> HexInput {
        let size = min(self.max_size, DUMMY_BYTES_MAX);
        HexInput::new(vec![0; size])
    }
}

impl<S> RandHexGenerator<S>
where
    S: HasRand,
{
    /// Returns a new [`RandBytesGenerator`], generating up to `max_size` random bytes.
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self {
            max_size,
            phantom: PhantomData,
        }
    }
}

// {"depth":1,"gas":"0x1337","gasCost":"0x0","memory":"0x","op":34,"opName":"","pc":0,"stack":[],"storage":{}}
// {"error":"EVM: Bad instruction 22","gasUsed":"0x1337","time":141}
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(untagged, rename_all = "camelCase")]
enum EVMLog {
    #[serde(rename_all = "camelCase")]
    Operation {
        depth: u8,
        gas: String,
        gas_cost: String,
        memory: String,
        op: u8,
        op_name: String,
        pc: u64,
        stack: Vec<String>,
        #[serde(default)]
        storage: BTreeMap<String, String>,
        #[serde(default)]
        error: Option<String>,
        #[serde(flatten)]
        extra: std::collections::HashMap<String, serde_json::Value>,
    },
    #[serde(rename_all = "camelCase")]
    Error {
        error: String,
        gas_used: String,
        time: u64,
    },
    #[serde(rename_all = "camelCase")]
    Ouptut {
        output: String,
        gas_used: String,
        time: u64,
    },
}

#[derive(PackedStruct, Clone, Default)]
#[packed_struct(bit_numbering = "msb0")]
pub struct TypeHash {
    #[packed_field(bits = "0")]
    mem_flag: bool,
    #[packed_field(bits = "1..=4")]
    t1: u8,
    #[packed_field(bits = "5..=7")]
    t2: u8,
    #[packed_field(bits = "8..=15")]
    opccode: u8,
}

#[derive(Debug, Clone)]
pub struct EVMTypeHashFeedback {
    name: String,
}

impl Named for EVMTypeHashFeedback {
    fn name(&self) -> &str {
        &self.name
    }
}

impl EVMTypeHashFeedback {
    pub fn new(name: &str, stdout: &StdOutObserver) -> Self {
        Self {
            name: name.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EVMFeedbackState {
    name: String,
    history: BitVec<u32>,
}
impl FeedbackState for EVMFeedbackState {}
impl Named for EVMFeedbackState {
    fn name(&self) -> &str {
        &self.name
    }
}

/// A `typehash`-based feedback, see [the `NeoDiff` paper](https://github.com/fgsect/NeoDiff/raw/main/roots21-2.pdf) for explanation
impl<I, S> Feedback<I, S> for EVMTypeHashFeedback
where
    I: Input,
    S: HasClientPerfMonitor,
{
    type FeedbackState = EVMFeedbackState;

    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        feedback_state: &mut Self::FeedbackState,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &libafl::executors::ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        // from https://github.com/fgsect/NeoDiff/blob/ad5d1250238fcb3bc8a8ddfe0d0dcefd5703324b/EVMFuzz.py#L40

        // generate a filename
        //let mut checksum = AHasher::default();
        let mut res = false;

        let stdout_observer = observers
            .match_name::<StdOutObserver>("StdOutObserver2")
            .unwrap();
        let stdout = stdout_observer.stdout.as_ref().unwrap();
        let mut is_error = false;

        let json_log: Vec<EVMLog> = stdout
            .split('\n')
            .map(|line| serde_json::from_str(line))
            .filter(|x| x.is_ok())
            .map(|res| res.unwrap())
            .collect();

        //json_log.as_slice().windows(2).for_each(|[curr, next]| {
        for window in json_log.as_slice().windows(2) {
            let curr = &window[0];
            let next = &window[1];
            let mut type_hash = TypeHash::default();

            match curr {
                EVMLog::Operation { op, .. } if *op == 253 => {
                    // ignore REVERT opcode
                    continue;
                }
                EVMLog::Operation { op, gas_cost, .. } => {
                    //checksum.write(&[*op]);
                    //checksum.write(gas_cost.as_bytes());
                    match next {
                        EVMLog::Error { error, .. } => {
                            is_error = true;
                        }
                        EVMLog::Operation {
                            memory, op, stack, ..
                        } => {
                            let mut pos = &mut type_hash.t1;
                            for item in stack {
                                //checksum.write(item.as_bytes());
                                if u32::from_str_radix(item, 16).is_ok() {
                                    *pos = 1;
                                } else if item.len() == 40 || item.len() == 42 {
                                    *pos = 2;
                                } else if item.len() > 42 {
                                    *pos = 3;
                                // ignoring elif len(item) <= 0xFFFFFFFFFFFFFFFF:
                                } else if item.len() < 40 {
                                    *pos = 5;
                                }

                                /*if pos == &mut type_hash.t1 {
                                    pos = &mut type_hash.t2;
                                } else {
                                    // we alrady have two params.
                                    break;
                                }*/
                                pos = &mut type_hash.t2;
                            }
                            if memory.len() > 2 {
                                *pos |= 6;
                            }
                            //checksum.write(memory.as_bytes());
                        }
                        EVMLog::Ouptut { .. } => (),
                    }
                }
                EVMLog::Error { error, .. } => {
                    if error.len() > 0 {
                        is_error = true;
                    }
                }
                _ => (),
            }
            // Todo: write log to somewhere?
            // Tdoo2: Find out if interesting.

            let arr = type_hash.pack().unwrap();
            let idx = (((arr[0] as u16) << 8) | arr[1] as u16) as usize;

            // eprintln!("IDX {} {}", idx, feedback_state.history.get(idx).unwrap());

            if feedback_state.history.get(idx).unwrap() == false {
                res = true;
                feedback_state.history.set(idx, true);
            }
        }

        Ok(res)
    }

    fn init_state(&mut self) -> Result<Self::FeedbackState, Error> {
        Ok(EVMFeedbackState {
            name: self.name().to_string(),
            history: BitVec::from_elem(u16::MAX.into(), false),
        })
    }
}

fn observer_hash(stdout_observer: &StdOutObserver) -> u64 {
    let mut is_error = false;
    let mut checksum = AHasher::default();

    eprintln!(
        ">>> {} {}",
        stdout_observer.name(),
        &stdout_observer.stdout.as_ref().unwrap()
    );
    let stdout = stdout_observer.stdout.as_ref().unwrap();
    let json_log: Vec<EVMLog> = stdout
        .split('\n')
        //.map(|line| { let x = serde_json::from_str(line); eprintln!("{:?} {}", &x, line); x })
        .map(|line| serde_json::from_str(line))
        .filter(|x| x.is_ok())
        .map(|res| res.unwrap())
        .collect();
    eprintln!("JSON {:?}", &json_log);

    for window in json_log.as_slice().windows(2) {
        let curr = &window[0];
        let next = &window[1];

        match curr {
            EVMLog::Operation { op, .. } if *op == 253 => {
                // ignore REVERT opcode
                continue;
            }
            EVMLog::Operation { op, gas_cost, .. } => {
                checksum.write(&[*op]);
                checksum.write(gas_cost.as_bytes());
                match next {
                    EVMLog::Error { error, .. } => {
                        is_error = true;
                    }
                    EVMLog::Operation {
                        memory, op, stack, ..
                    } => {
                        for item in stack {
                            checksum.write(item.as_bytes());
                        }
                        checksum.write(memory.as_bytes());
                    }
                    EVMLog::Ouptut { .. } => (),
                }
            }
            EVMLog::Error { error, .. } => {
                if error.len() > 0 {
                    is_error = true;
                }
            }
            _ => (),
        }
    }

    checksum.finish()
}

/// The main fn, `no_mangle` as it is a C symbol
pub fn main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    //RegistryBuilder::register::<Tokens>();

    let workdir = env::current_dir().unwrap();

    let opt = Opt::parse();

    //let cores = opt.cores;
    //let broker_port = opt.broker_port;
    //let remote_broker_addr = opt.remote_broker_addr;
    let input_dirs = opt.input;
    let output_dir = opt.output;
    let token_files = opt.tokens;
    let timeout_ms = opt.timeout;

    println!("Workdir: {:?}", workdir.to_string_lossy().to_string());

    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    let monitor = MultiMonitor::new(|s| println!("{}", s));
    let mut mgr = SimpleEventManager::new(monitor);

    //let mut run_client = |state: Option<StdState<_, _, _, _, _, _>>, mut mgr, _core_id| {
    let stdout1 = StdOutObserver::new("StdOutObserver1".into());
    let stdout2 = StdOutObserver::new("StdOutObserver2".into());

    let mut objective = DiffFeedback::new("differ", &stdout1, &stdout2, |o1, o2| {
        if observer_hash(o1) == observer_hash(o2) {
            DiffResult::Equal
        } else {
            eprintln!("DIFFFFFF");
            DiffResult::Diff
        }
    })
    .unwrap();

    let mut th_feedback = EVMTypeHashFeedback::new("evm_typehash", &stdout1);

    // If not restarting, create a State from scratch
    let mut state = //state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::with_seed(current_nanos()),
                // Corpus that will be evolved, we keep it in memory for performance
                InMemoryCorpus::new(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new(output_dir.clone()).unwrap(),
                // States of the feedbacks.
                // They are the data related to the feedbacks that you want to persist in the State.
                &mut th_feedback,
                &mut objective,
            )
            .unwrap()
        //});
        ;

    // Create a dictionary if not existing
    if state.metadata().get::<Tokens>().is_none() {
        for tokens_file in &token_files {
            state.add_metadata(Tokens::from_file(tokens_file).unwrap());
        }
    }

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, th_feedback, objective);

    let ce1 = CommandExecutor::builder()
        .program("./go-ethereum/build/bin/evm")
        .args(&[
            "--json",
            "--sender",
            "0x00",
            "--receiver",
            "0x00",
            "--gas",
            "0x1337",
            "--code",
        ])
        .arg_input_arg()
        .arg("run")
        .stdout_observer("StdOutObserver1".into())
        .build(tuple_list!(stdout1))
        .unwrap();

    let ce2 = CommandExecutor::builder()
        .program("./openethereum/target/release/openethereum-evm")
        .args(&[
            "--chain",
            "./openethereum/crates/ethcore/res/chainspec/test/istanbul_test.json",
            "--gas",
            "1337",
            "--json",
            "--code",
        ])
        .arg_input_arg()
        .stdout_observer("StdOutObserver2".into())
        .build(tuple_list!(stdout2))
        .unwrap();

    let mut diff_executor = DiffExecutor::new(ce1, ce2);

    // Setup a basic mutator
    let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
    let mutational = StdMutationalStage::new(mutator);

    // The order of the stages matter!
    let mut stages = tuple_list!(mutational);

    // In case the corpus is empty (on first run), reset
    if state.corpus().count() < 1 {
        if input_dirs.is_empty() {
            // Generator of printable bytearrays of max size 32
            let mut generator = RandHexGenerator::new(32);

            // Generate 8 initial inputs
            state
                .generate_initial_inputs(
                    &mut fuzzer,
                    &mut diff_executor,
                    &mut generator,
                    &mut mgr,
                    8,
                )
                .expect("Failed to generate the initial corpus");
            println!(
                "We imported {} inputs from the generator.",
                state.corpus().count()
            );
        } else {
            println!("Loading from {:?}", &input_dirs);
            // Load from disk
            state
                .load_initial_inputs(&mut fuzzer, &mut diff_executor, &mut mgr, &input_dirs)
                .unwrap_or_else(|_| panic!("Failed to load initial corpus at {:?}", &input_dirs));
            println!("We imported {} inputs from disk.", state.corpus().count());
        }
    }

    fuzzer
        .fuzz_loop(&mut stages, &mut diff_executor, &mut state, &mut mgr)
        .unwrap();
    //Ok(())
    //};

    /*match Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_name("default"))
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        .broker_port(broker_port)
        .remote_broker_addr(remote_broker_addr)
        //.stdout_file(Some("/dev/null"))
        .build()
        .launch()
    {
        Ok(_) | Err(Error::ShuttingDown) => (),
        Err(e) => panic!("{:?}", e),
    };*/
}
