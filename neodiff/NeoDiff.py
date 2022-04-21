# Main classes for NeoDiff

import subprocess
import random
import struct
from logzero import logger
from itertools import chain
import json
import os
import argparse
import secrets
import time
from filelock import Timeout, FileLock
import binascii

typehash_MAP = {}


class open_create:
    def __init__(self, filename, mode="r"):
        self.filename = filename
        self.mode = mode
        self.fp = None

    def __enter__(self):
        os.makedirs(os.path.dirname(self.filename), exist_ok=True)
        self.fp = open(self.filename, self.mode)
        return self

    def __exit__(self, type, value, traceback):
        self.fp.close()

    def write(self, m):
        self.fp.write(m)

    def read(self):
        self.fp.read()


class VMRunnerProcess:
    def __init__(self, cli):
        self.cli = cli
        self.vm = None
        self.reset()
        self.code = ""

    def reset(self):
        pass

    def exit(self):
        pass

    def prepare_cli(self, code):
        raise Exception("please implement or return empty []")

    def run_vm(self, code):
        self.code = code

        cli = self.cli + self.prepare_cli(code)
        # logger.info("run: {}".format(' '.join(cli)))
        p = subprocess.Popen(cli, stdout=subprocess.PIPE)
        try:
            out, err = p.communicate(timeout=2) 
        except subprocess.TimeoutExpired as e:
            logger.exception(e)
            logger.info(code)
            out = []
            err = []
        except OSError as e:
            logger.exception(e)
            logger.info(code)
            out = []
            err = []
        # logger.info("{}\n{}".format(cli, out))
        j = []
        if out:
            j = [json.loads(line) for line in out.splitlines() if line.startswith(b"{")]
        # logger.info(j)
        return j


class VMRunnerIO:
    def __init__(self, cli):
        self.cli = cli
        self.vm = None
        self.reset()
        self.code = ""

    def reset(self):
        if self.vm:
            self.exit()
        self.vm = subprocess.Popen(
            self.cli, stdin=subprocess.PIPE, stdout=subprocess.PIPE
        )

    def exit(self):
        if self.vm:
            self.vm.stdin.write(b"\x00\x00")

    def run_vm(self, code):
        try:
            self.code = code
            code = binascii.unhexlify(code)

            code_length = struct.pack("H", len(code))
            # logger.info('write code_length')
            self.vm.stdin.write(code_length)
            # logger.info('write code')
            self.vm.stdin.write(code)
            # logger.info('flush')
            self.vm.stdin.flush()

            # logger.info('read size')
            out_size_raw = self.vm.stdout.read(4)
            # logger.info(out_size_raw)
            out_size = struct.unpack("I", out_size_raw)[0]
            # logger.info(out_size)
            # logger.info('read out')
            out = self.vm.stdout.read(out_size)
            return json.loads(out)
        except Exception as e:
            logger.exception(e)
            time.sleep(1)
            self.reset()
            return []
        # logger.info('load json')


def minimize_code_keep_state(code, state, python, csharp):
    minimizing = True
    while minimizing:
        _code = code[:-1]
        if len(_code) > 0:
            vm1_out, vm2_out = run_both_with_code(code, python, csharp)
            if state in vm1_out and state in vm2_out:
                code = _code
                continue
            return code


def get_typehash(state):
    return "{}_{}".format(state["opcode"], state["data"])


class FuzzerConfig:
    def __init__(self, name):
        self.new_typehash_file = "RESULTS/{}/fuzzer_new_typehash_map.{}.json".format(
            name, random.randint(0, 9999999)
        )
        self.typehash_file = "RESULTS/{}/fuzzer_typehash_map.json".format(name)
        self.stats = {
            "execs": 0,
            "diffs": 0,
            "diffs_new": 0,
            "diffs_new_opcode": 0,
            "new_typehashes": 0,
            "typehashes": 0,
        }
        self.name = name
        self.vm1 = None
        self.vm2 = None
        self.typehash_map = {}
        self.new_typehash_map = {}
        self.current_coverage = {}
        self.roundsize = 1000
        self.vm1_queue = []
        self.vm2_queue = []
        self.clean_exit_opcode = None
        self.logger_execs = 0

    def sync_fuzzers(self):
        # logger.info(self.stats)

        # {"8_2": [{"vm1_code": "0800e331e97d992c8e", "vm2_code": "0800e331e97d992c8e", "vm1": {"opcode": 8, "ret": null, "data": "2", "vmstate": 0, "crash": false, "checksum": "3fd2b9ac23400c133f79280ff41d366263e76e96"}, "vm2": {"opcode": 8, "ret": null, "data": "2", "vmstate": 0, "crash": false, "checksum": "3fd2b9ac23400c133f79280ff41d366263e76e96"}}]
        if self.typehash_file and os.path.isfile(self.typehash_file):
            # logger.info('open self.typehash_file')
            with open(self.typehash_file, "r") as f:
                sync = f.read()
                if sync:
                    j = json.loads(sync)
                    self.typehash_map = j
                    for typehash in self.new_typehash_map:
                        if typehash not in self.typehash_map:
                            self.typehash_map[typehash] = []
                        self.typehash_map[typehash].append(
                            self.new_typehash_map[typehash][-1]
                        )

        with open_create(self.new_typehash_file, "w") as f:
            f.write(json.dumps(self.new_typehash_map))

        with open_create(self.typehash_file, "w") as f:
            f.write(json.dumps(self.typehash_map))

        tmp_state = {
            "execs": 0,
            "diffs": 0,
            "diffs_new": 0,
            "diffs_new_opcode": 0,
            "new_typehashes": 0,
            "typehashes": 0,
        }

        if os.path.isfile("RESULTS/{}/fuzzer_stats.json".format(self.name)):
            # logger.info('is file')
            with open("RESULTS/{}/fuzzer_stats.json".format(self.name), "r") as f:
                sync = f.read()
                # logger.info(sync)
                if sync:
                    tmp_state = json.loads(sync)
                    # logger.info(tmp_state)

        tmp_state["execs"] += self.stats["execs"]
        tmp_state["diffs"] += self.stats["diffs"]
        tmp_state["diffs_new"] += self.stats["diffs_new"]
        tmp_state["diffs_new_opcode"] += self.stats["diffs_new_opcode"]
        tmp_state["new_typehashes"] += len(self.new_typehash_map.keys())
        tmp_state["typehashes"] += len(self.typehash_map.keys())

        self.stats = tmp_state

        with open_create("RESULTS/{}/fuzzer_stats.json".format(self.name), "w") as f:
            f.write(json.dumps(tmp_state))

        # logger.info(tmp_state)

    def pre_round(self, seed=None):
        raise Exception("implement setting up queue here")

    def post_round(self, seed=None):
        raise Exception("implement anything you want once the round is done")

    def run_both_consume_queue(self):
        vm1_code = self.get_job_vm1()
        vm2_code = self.get_job_vm2()
        return self.run_both_with_code(vm1_code, vm2_code)

    def run_both_with_code(self, vm1_code, vm2_code):
        vm1_out = self.vm1.run_vm(vm1_code)
        vm2_out = self.vm2.run_vm(vm2_code)
        self.stats["execs"] += 2
        self.logger_execs += 1
        vm1_out_clean = self.clean_vm1_out(vm1_out)
        vm2_out_clean = self.clean_vm2_out(vm2_out)
        return (vm1_out_clean, vm2_out_clean)

    def is_new_coverage_better(self, new_coverage, old_coverage):
        raise Exception("check which is better new_coverage, old_coverage")

    def minimize_current_coverage(self):
        raise Exception("minimize current coverage")

    def clean_vm1_out(self, out):
        return out

    def clean_vm2_out(self, out):
        return out

    def get_job_vm1(self):
        return self.vm1_queue.pop()

    def get_job_vm2(self):
        return self.vm2_queue.pop()

    def merge_coverage(self):
        for typehash in self.current_coverage.keys():
            new_coverage = self.current_coverage[typehash]

            if typehash not in self.typehash_map:
                pass
                # logger.info('add {} to typehash_map'.format(typehash))
            else:
                old_coverage = self.typehash_map[typehash][-1]
                if not self.is_new_coverage_better(new_coverage, old_coverage):
                    continue

            # self.typehash_map[typehash].append(new_coverage)
            if typehash not in self.new_typehash_map:
                self.new_typehash_map[typehash] = []
                # logger.info('add {} to new_typehash_map'.format(typehash))

            self.new_typehash_map[typehash].append(new_coverage)

    def fuzz(self):
        start_time_campaign = time.time()
        loop = True
        round_nr = 0
        self.sync_fuzzers()
        while loop:
            round_nr += 1

            start = time.time()
            self.pre_round()
            self.new_typehash_map = {}  # reset the tyephash coverage map for this round

            self.stats = {"execs": 0, "diffs": 0, "diffs_new": 0, "diffs_new_opcode": 0}

            for exec_nr in range(0, self.roundsize):
                if exec_nr % 100 == 0:
                    logger.info("{}. {}/{}".format(round_nr, exec_nr, self.roundsize))

                # open('/tmp/trace_now', 'a').close()
                ############### RUN THE VMS ###############
                vm1_out, vm2_out = self.run_both_consume_queue()
                ############### RUN THE VMS ###############
                # os.remove("/tmp/trace_now")

                self.current_coverage = {}

                if (len(vm1_out) == 0 and len(vm2_out) != 0) or (
                    len(vm1_out) != 0 and len(vm2_out) == 0
                ):
                    logger.info(
                        "we had a timeout or crash in one VM len output: {} vs. {}".format(
                            len(vm1_out), len(vm2_out)
                        )
                    )

                    diff_fname = "RESULTS/{}/diffs/typehash_crash".format(self.name)
                    if not os.path.isfile(diff_fname):
                        self.stats["diffs_new"] += 1

                    self.stats["diffs"] += 1
                    with open_create(diff_fname, "a+") as f:
                        out = "-------------------\n"
                        out += "vm1_code: {}\n".format(self.vm1.code)
                        out += "vm1_code: {}\n".format(self.vm2.code)
                        out += "vm1: {}\n".format(vm1_out)
                        out += "vm2: {}\n".format(vm2_out)
                        logger.info(diff_fname)
                        logger.info(out)
                        f.write(out)

                for i in range(0, min(len(vm1_out), len(vm2_out))):
                    vm1 = vm1_out[i]
                    vm2 = vm2_out[i]
                    # at least one didn't crash and checksum diff
                    if (
                        (not vm1["crash"] or not vm2["crash"])
                        and vm1["checksum"] != vm2["checksum"]
                        or vm1["crash"]
                        and not vm2["crash"]
                        or not vm1["crash"]
                        and vm2["crash"]
                    ):

                        logger.info(vm1)
                        logger.info(vm2)

                        diff_fname = "RESULTS/{}/diffs/typehash_{}-{}_time:{}_execs:{}".format(
                            self.name, get_typehash(vm1), get_typehash(vm2),
                            int(time.time() - start_time_campaign),
                            self.logger_execs
                        )
                        if not os.path.isfile(diff_fname):
                            self.stats["diffs_new"] += 1

                        self.stats["diffs"] += 1
                        with open_create(diff_fname, "a+") as f:
                            out = "-------------------\n"
                            out += "vm1_code: {}\n".format(self.vm1.code)
                            out += "vm1_code: {}\n".format(self.vm2.code)
                            out += "vm1: {}\n".format(vm1)
                            out += "vm2: {}\n".format(vm2)
                            logger.info(diff_fname)
                            logger.info(out)
                            f.write(out)

                        if vm2["opcode"] == vm1["opcode"]:
                            opdiff_fname = "RESULTS/{}/diffs/opcode_{}".format(
                                self.name, vm2["opcode"]
                            )
                            if not os.path.isfile(opdiff_fname):
                                self.stats["diffs_new_opcode"] += 1
                            with open_create(opdiff_fname, "a+") as f:
                                f.write("{}\n".format(diff_fname))
                        break
                    elif not vm1["crash"] and not vm2["crash"]:
                        # if it was a normal execution without issues
                        if self.clean_exit_opcode == None or (
                            self.clean_exit_opcode != None
                            and vm1["opcode"] != self.clean_exit_opcode
                            and vm2["opcode"] != self.clean_exit_opcode
                        ):
                            if get_typehash(vm1) == get_typehash(vm2):
                                typehash = get_typehash(vm1)
                                # remember working type hash in map
                                if typehash not in self.current_coverage:
                                    self.current_coverage[typehash] = {
                                        "vm1_code": self.vm1.code,
                                        "vm2_code": self.vm2.code,
                                        "vm1": vm1,
                                        "vm2": vm2,
                                    }

                ######### MINIMIZING and COVERAGE #####
                self.minimize_current_coverage()
                self.merge_coverage()
                ######### MINIMIZING and COVERAGE #####

            lock = FileLock("/tmp/{}_sync_fuzzers.lock".format(self.name))
            with lock:

                self.sync_fuzzers()

                with open_create(
                    "RESULTS/{}/stats_typehashes_new".format(self.name), "a+"
                ) as f:
                    out = "{}\n".format(len(self.new_typehash_map.keys()))
                    logger.info("typehashes_new: {}".format(out.strip()))
                    f.write(out)
                with open_create(
                    "RESULTS/{}/stats_typehashes".format(self.name), "a+"
                ) as f:
                    out = "{}\n".format(len(self.typehash_map.keys()))
                    logger.info("typehashes: {}".format(out.strip()))
                    f.write(out)

                with open_create("RESULTS/{}/stats_diffs".format(self.name), "a+") as f:
                    out = "{}\n".format(self.stats["diffs"])
                    logger.info("diffs: {}".format(out.strip()))
                    f.write(out)
                with open_create(
                    "RESULTS/{}/stats_diffs_new".format(self.name), "a+"
                ) as f:
                    out = "{}\n".format(self.stats["diffs_new"])
                    logger.info("diffs_new: {}".format(out.strip()))
                    f.write(out)
                with open_create(
                    "RESULTS/{}/stats_diffs_new_opcode".format(self.name), "a+"
                ) as f:
                    out = "{}\n".format(self.stats["diffs_new_opcode"])
                    logger.info("diffs_new_opcode: {}".format(out.strip()))
                    f.write(out)
                with open_create("RESULTS/{}/stats_time".format(self.name), "a+") as f:
                    out = "{}\n".format(int(time.time() - start))
                    logger.info("time: {}".format(out.strip()))
                    f.write(out)
                with open_create("RESULTS/{}/stats_execs".format(self.name), "a+") as f:
                    out = "{}\n".format(self.stats["execs"])
                    logger.info("execs: {}".format(out.strip()))
                    f.write(out)
                with open_create(
                    "RESULTS/{}/stats_execs_per_sec".format(self.name), "a+"
                ) as f:
                    out = "{}\n".format(self.stats["execs"] / (time.time() - start))
                    logger.info("execs_per_sec: {}".format(out.strip()))
                    f.write(out)

            self.post_round()

        logger.info("done")
        python.exit()
        csharp.exit()
        exit(0)
