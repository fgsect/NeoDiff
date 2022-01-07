# Neo Specific bytecode generator

import random
import struct
import os
import binascii
from logzero import logger
import secrets
import json
from neodiff.PyDiffGenerator import SCInteger

# code = os.urandom(0xfff).hex()


known_code = {}
known_ops = set([])


def random_bytes(n):
    return bytes(random.getrandbits(8) for _ in range(n))


def createSyscall():
    syscalls = [
        "AntShares.Account.GetBalance",
        "AntShares.Account.GetScriptHash",
        "AntShares.Account.GetVotes",
        "AntShares.Account.SetVotes",
        "AntShares.Asset.Create",
        "AntShares.Asset.GetAdmin",
        "AntShares.Asset.GetAmount",
        "AntShares.Asset.GetAssetId",
        "AntShares.Asset.GetAssetType",
        "AntShares.Asset.GetAvailable",
        "AntShares.Asset.GetIssuer",
        "AntShares.Asset.GetOwner",
        "AntShares.Asset.GetPrecision",
        "AntShares.Asset.Renew",
        "AntShares.Attribute.GetData",
        "AntShares.Attribute.GetUsage",
        "AntShares.Block.GetTransaction",
        "AntShares.Block.GetTransactionCount",
        "AntShares.Block.GetTransactions",
        "AntShares.Blockchain.GetAccount",
        "AntShares.Blockchain.GetAsset",
        "AntShares.Blockchain.GetBlock",
        "AntShares.Blockchain.GetContract",
        "AntShares.Blockchain.GetHeader",
        "AntShares.Blockchain.GetHeight",
        "AntShares.Blockchain.GetTransaction",
        "AntShares.Blockchain.GetValidators",
        "AntShares.Contract.Create",
        "AntShares.Contract.Destroy",
        "AntShares.Contract.GetScript",
        "AntShares.Contract.GetStorageContext",
        "AntShares.Contract.Migrate",
        "AntShares.Header.GetConsensusData",
        "AntShares.Header.GetHash",
        "AntShares.Header.GetMerkleRoot",
        "AntShares.Header.GetNextConsensus",
        "AntShares.Header.GetPrevHash",
        "AntShares.Header.GetTimestamp",
        "AntShares.Header.GetVersion",
        "AntShares.Input.GetHash",
        "AntShares.Input.GetIndex",
        "AntShares.Output.GetAssetId",
        "AntShares.Output.GetScriptHash",
        "AntShares.Output.GetValue",
        "AntShares.Runtime.CheckWitness",
        "AntShares.Runtime.GetTrigger",
        "AntShares.Runtime.Log",
        "AntShares.Runtime.Notify",
        "AntShares.Storage.Delete",
        "AntShares.Storage.Get",
        "AntShares.Storage.GetContext",
        "AntShares.Storage.Put",
        "AntShares.Transaction.GetAttributes",
        "AntShares.Transaction.GetHash",
        "AntShares.Transaction.GetInputs",
        "AntShares.Transaction.GetOutpus",
        "AntShares.Transaction.GetReferences",
        "AntShares.Transaction.GetType",
        "Neo.Account.GetBalance",
        "Neo.Account.GetScriptHash",
        "Neo.Account.GetVotes",
        "Neo.Asset.Create",
        "Neo.Asset.GetAdmin",
        "Neo.Asset.GetAmount",
        "Neo.Asset.GetAssetId",
        "Neo.Asset.GetAssetType",
        "Neo.Asset.GetAvailable",
        "Neo.Asset.GetIssuer",
        "Neo.Asset.GetOwner",
        "Neo.Asset.GetPrecision",
        "Neo.Asset.Renew",
        "Neo.Attribute.GetData",
        "Neo.Attribute.GetUsage",
        "Neo.Block.GetTransaction",
        "Neo.Block.GetTransactionCount",
        "Neo.Block.GetTransactions",
        "Neo.Blockchain.GetAccount",
        "Neo.Blockchain.GetAsset",
        "Neo.Blockchain.GetBlock",
        "Neo.Blockchain.GetContract",
        "Neo.Blockchain.GetHeader",
        "Neo.Blockchain.GetHeight",
        "Neo.Blockchain.GetTransaction",
        "Neo.Blockchain.GetTransactionHeight",
        "Neo.Blockchain.GetValidators",
        "Neo.Contract.Create",
        "Neo.Contract.Destroy",
        "Neo.Contract.GetScript",
        "Neo.Contract.GetStorageContext",
        "Neo.Contract.IsPayable",
        "Neo.Contract.Migrate",
        "Neo.Enumerator.Concat",
        "Neo.Enumerator.Create",
        "Neo.Enumerator.Next",
        "Neo.Enumerator.Value",
        "Neo.Header.GetConsensusData",
        "Neo.Header.GetHash",
        "Neo.Header.GetIndex",
        "Neo.Header.GetMerkleRoot",
        "Neo.Header.GetNextConsensus",
        "Neo.Header.GetPrevHash",
        "Neo.Header.GetTimestamp",
        "Neo.Header.GetVersion",
        "Neo.Input.GetHash",
        "Neo.Input.GetIndex",
        "Neo.InvocationTransaction.GetScript",
        "Neo.Iterator.Create",
        "Neo.Iterator.Key",
        "Neo.Iterator.Keys",
        "Neo.Iterator.Next",
        "Neo.Iterator.Value",
        "Neo.Iterator.Values",
        "Neo.Output.GetAssetId",
        "Neo.Output.GetScriptHash",
        "Neo.Output.GetValue",
        "Neo.Runtime.CheckWitness",
        "Neo.Runtime.Deserialize",
        "Neo.Runtime.GetTime",
        "Neo.Runtime.GetTrigger",
        "Neo.Runtime.Log",
        "Neo.Runtime.Notify",
        "Neo.Runtime.Serialize",
        "Neo.Storage.Delete",
        "Neo.Storage.Find",
        "Neo.Storage.Get",
        "Neo.Storage.GetContext",
        "Neo.Storage.GetReadOnlyContext",
        "Neo.Storage.Put",
        "Neo.StorageContext.AsReadOnly",
        "Neo.Transaction.GetAttributes",
        "Neo.Transaction.GetHash",
        "Neo.Transaction.GetInputs",
        "Neo.Transaction.GetOutputs",
        "Neo.Transaction.GetReferences",
        "Neo.Transaction.GetType",
        "Neo.Transaction.GetUnspentCoins",
        "Neo.Transaction.GetWitnesses",
        "Neo.Witness.GetVerificationScript",
        "System.Block.GetTransaction",
        "System.Block.GetTransactionCount",
        "System.Block.GetTransactions",
        "System.Blockchain.GetBlock",
        "System.Blockchain.GetContract",
        "System.Blockchain.GetHeader",
        "System.Blockchain.GetHeight",
        "System.Blockchain.GetTransaction",
        "System.Blockchain.GetTransactionHeight",
        "System.Contract.Destroy",
        "System.Contract.GetStorageContext",
        "System.ExecutionEngine.GetCallingScriptHash",
        "System.ExecutionEngine.GetEntryScriptHash",
        "System.ExecutionEngine.GetExecutingScriptHash",
        "System.ExecutionEngine.GetScriptContainer",
        "System.Header.GetHash",
        "System.Header.GetIndex",
        "System.Header.GetPrevHash",
        "System.Header.GetTimestamp",
        "System.Header.GetVersion",
        "System.Runtime.CheckWitness",
        "System.Runtime.Deserialize",
        "System.Runtime.GetTime",
        "System.Runtime.GetTrigger",
        "System.Runtime.Log",
        "System.Runtime.Notify",
        "System.Runtime.Serialize",
        "System.Storage.Delete",
        "System.Storage.Get",
        "System.Storage.GetContext",
        "System.Storage.GetReadOnlyContext",
        "System.Storage.Put",
        "System.StorageContext.AsReadOnly",
        "System.Transaction.GetHash",
    ]
    syscall = random.choice(syscalls)
    return b"\x68" + struct.pack("B", len(syscall)) + bytes(syscall, "ascii")


def run(seed, amount=1, probability=1, new_typehash_file=None, typehash_file=None):
    if seed == None:
        seed = secrets.randbelow(1 << 32)
    random.seed(seed)
    codes = []

    all_coverage = {}
    new_coverage = {}

    if typehash_file and os.path.isfile(typehash_file):
        with open(typehash_file) as f:
            all_coverage = json.loads(f.read())

    if new_typehash_file and os.path.isfile(new_typehash_file):
        with open(new_typehash_file) as f:
            new_coverage = json.loads(f.read())

    for _ in range(0, amount):
        scinteger = SCInteger(None)
        last_feedback = 0
        feedback = []
        code = b""
        while len(code) < 0x7F:
            # select what type of code generator we use
            c = random.randint(0, 20)

            if c == 0:
                code += random_bytes(random.randint(0x1, 0xF))
            elif c > 0 and c < 5:  # pick random code from all coverage
                if len(all_coverage.keys()) > 0:
                    rand_state = random.choice(list(all_coverage.keys()))
                    rand_code = binascii.unhexlify(
                        random.choice(all_coverage[rand_state])["vm1_code"]
                    )
                    d = random.randint(0, 2)
                    if d == 0:
                        code += rand_code
                    elif d == 1:
                        rand_state2 = random.choice(list(all_coverage.keys()))
                        rand_code2 = binascii.unhexlify(
                            random.choice(all_coverage[rand_state2])["vm1_code"]
                        )

                        if len(rand_code) > 3 and len(rand_code2) > 3:
                            split1 = random.randint(1, len(rand_code) - 1)
                            split2 = random.randint(1, len(rand_code2) - 1)
                            code += rand_code[:split1] + rand_code2[split2:]
                    elif d == 2:
                        pos = random.randint(0, len(rand_code) - 1)
                        code += rand_code[:pos] + random_bytes(1) + rand_code[pos + 1 :]
            elif c >= 5 and c <= 20:  # pick random from new coverage
                if len(new_coverage.keys()) > 0:
                    rand_state = random.choice(list(new_coverage.keys()))
                    rand_code = binascii.unhexlify(
                        random.choice(new_coverage[rand_state])["vm1_code"]
                    )
                    d = random.randint(0, 2)
                    if d == 0:
                        code += rand_code
                    elif d == 1:
                        rand_state2 = random.choice(list(new_coverage.keys()))
                        rand_code2 = binascii.unhexlify(
                            random.choice(new_coverage[rand_state2])["vm1_code"]
                        )
                        if len(rand_code) > 3 and len(rand_code2) > 3:
                            split1 = random.randint(1, len(rand_code) - 1)
                            split2 = random.randint(1, len(rand_code2) - 1)
                            code += rand_code[:split1] + rand_code2[split2:]
                    elif d == 2:
                        pos = random.randint(0, len(rand_code) - 1)
                        code += rand_code[:pos] + random_bytes(1) + rand_code[pos + 1 :]
        codes.append(code + b"\x66")  # add a RET to signal successful execution
    return codes


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", "-s", default=None, type=int, help="The initial seed")

    args = parser.parse_args()

    print(run(seed=args.seed))
