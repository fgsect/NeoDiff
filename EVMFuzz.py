#!/usr/bin/env python3
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
import hashlib
import binascii

from NeoDiff import FuzzerConfig, VMRunnerProcess
import EVMDiffGenerator


class ENeoDiffConfig(FuzzerConfig):
    def pre_round(self):
        codes = EVMDiffGenerator.run(
            self.seed,
            self.roundsize,
            self.probability,
            self.new_typehash_file,
            self.typehash_file,
        )
        for code in codes:
            code = binascii.hexlify(code).decode("ascii")
            self.vm1_queue.append(code)
            self.vm2_queue.append(code)

    def post_round(self):
        pass

    # {"opcode": 24, "ret": null, "data": "33", "vmstate": 0, "crash": false, "checksum": "cc18e0d61c85b87441efddc503708b9e8253d53d"}
    def clean_vm1_out(self, out):
        new_out = []
        m = hashlib.sha1()
        for i in range(0, len(out) - 1):
            if "op" not in out[i]:
                continue
            if out[i]["op"] == 253:  # REVERT
                continue
            m.update(str(out[i]["op"]).encode("ascii"))
            m.update(str(out[i]["gasCost"]).encode("ascii"))
            typehash = ""

            crashed = False
            if ("error" in out[i + 1] and len(out[i + 1]["error"]) > 0) and (
                "op" not in out[i + 1] or "output" in out[i + 1]
            ):
                # logger.info(['error'])
                # logger.info(out[i+1])
                crashed = True
            elif "error" in out[i] and len(out[i]["error"]) > 0:
                crashed = True
            elif (
                "op" in out[i]
                and "stack" in out[i + 1]
                and "op" in out[i + 1]
                and out[i + 1]["op"] != 0
            ):
                # logger.info(out[i+1])
                for item in out[i + 1]["stack"][::-1]:
                    m.update(item.encode("ascii"))
                    if len(typehash) < 2:
                        if int(item, 16) == 1:
                            typehash += "1"
                        elif len(item) == 42 or len(item) == 40:
                            typehash += "2"
                        elif len(item) > 42:
                            typehash += "3"
                        elif len(item) <= 0xFFFFFFFFFFFFFFFF:
                            typehash += "4"
                        elif len(item) < 40:
                            typehash += "5"
                m.update(out[i + 1]["memory"].rstrip("0").encode("ascii"))
                if len(out[i + 1]["memory"]) > 2:
                    typehash += "6"
            else:
                pass
                # logger.info(out[i])
                # logger.info(out[i+1])

            new_out.append(
                {
                    "opcode": out[i]["op"],
                    "ret": None,
                    "data": typehash,
                    "crash": crashed,
                    "checksum": m.hexdigest(),
                }
            )
        # logger.info(new_out)
        return new_out

    def clean_vm2_out(self, out):
        return self.clean_vm1_out(out)

    def is_new_coverage_better(self, new_coverage, old_coverage):
        if len(new_coverage["vm1_code"]) < len(old_coverage["vm1_code"]):
            return True
        return False

    def minimize_current_coverage(self):
        typehashes = list(self.current_coverage.keys())
        minimizing = True
        code_cut = 2
        while len(typehashes) and minimizing:

            code = self.current_coverage[typehashes[0]]["vm1_code"]

            _code = code[:code_cut]
            if len(_code) == 0 or code_cut > len(code):
                break

            vm1_out, vm2_out = fuzzer.run_both_with_code(_code, _code)

            remaining_typehashes = []
            for typehash in typehashes:
                vm1 = self.current_coverage[typehash]["vm1"]
                vm2 = self.current_coverage[typehash]["vm2"]
                if vm1 in vm1_out and vm2 in vm2_out:
                    self.current_coverage[typehash]["vm1_code"] = _code
                    self.current_coverage[typehash]["vm2_code"] = _code
                else:
                    remaining_typehashes.append(typehash)

            typehashes = remaining_typehashes
            code_cut += 2


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", "-s", default=None, type=int, help="The initial seed")
    parser.add_argument("--name", "-n", default=None, type=str, help="name")
    parser.add_argument("--roundsize", "-r", default=1000, type=int, help="round size")
    parser.add_argument("--depth", "-d", default=50, type=int, help="execution depth")
    parser.add_argument("--probability", "-p", default=1, type=int, help="propability")

    args = parser.parse_args()

    fuzzer = ENeoDiffConfig(name=args.name)
    fuzzer.probability = args.probability
    fuzzer.roundsize = args.roundsize
    if args.seed:
        fuzzer.seed = args.seed
    else:
        fuzzer.seed = random.randint(0x0000000000000000, 0xFFFFFFFFFFFFFFFF)
    fuzzer.seed = args.seed

    fuzzer.vm1 = VMRunnerProcess(
        [
            "./go-ethereum/build/bin/evm",
            "--json",
            "--sender",
            "0x00",
            "--receiver",
            "0x00",
            "--gas",
            "0x1337",
        ]
    )
    fuzzer.vm1.prepare_cli = lambda code: ["--code", code, "run"]

    fuzzer.vm2 = VMRunnerProcess(
        [
            "./openethereum/target/release/openethereum-evm",
            "--chain",
            "./openethereum/crates/ethcore/res/chainspec/test/istanbul_test.json",
            "--gas",
            "1337",
            "--json",
        ]
    )
    fuzzer.vm2.prepare_cli = lambda code: ["--code", code]

    fuzzer.clean_exit_opcode = 0xF3

    fuzzer.fuzz()
