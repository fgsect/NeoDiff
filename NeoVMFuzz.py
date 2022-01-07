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
import binascii

from neodiff.NeoDiff import FuzzerConfig, VMRunnerIO, NeoVmDiffGenerator
import neodiff.NeoVmDiffGenerator


class NeoDiffFuzzerConfig(FuzzerConfig):
    def pre_round(self):
        codes = NeoVmDiffGenerator.run(
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

    def clean_vm2_out(self, out):
        for i in range(0, len(out)):
            if len(out) > i + 1:
                look_ahead = out[i + 1]
                if look_ahead["opcode"] == None:
                    out[i]["crash"] = True
        return out

    def clean_vm1_out(self, out):
        for i in range(0, len(out)):
            if len(out) > i + 1:
                look_ahead = out[i + 1]
                if look_ahead["opcode"] == None:
                    out[i]["crash"] = True
        return out

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


"""
python NeoVMFuzz.py --name 2k20o1p --roundsize 2000 --depth 20 --probability 1
python NeoVMFuzz.py --name 2k20o20p --roundsize 2000 --depth 20 --probability 20
python NeoVMFuzz.py --name 2k500o1p --roundsize 2000 --depth 500 --probability 1
python NeoVMFuzz.py --name 2k500o20p --roundsize 2000 --depth 500 --probability 20
"""

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", "-s", default=None, type=int, help="The initial seed")
    parser.add_argument("--name", "-n", default=None, type=str, help="name")
    parser.add_argument("--roundsize", "-r", default=1000, type=int, help="round size")
    parser.add_argument("--depth", "-d", default=50, type=int, help="execution depth")
    parser.add_argument("--probability", "-p", default=1, type=int, help="propability")

    args = parser.parse_args()

    fuzzer = NeoDiffFuzzerConfig(name=args.name)
    fuzzer.probability = args.probability
    fuzzer.roundsize = args.roundsize
    if args.seed:
        fuzzer.seed = args.seed
    else:
        fuzzer.seed = random.randint(0x0000000000000000, 0xFFFFFFFFFFFFFFFF)
    fuzzer.seed = args.seed
    fuzzer.vm1 = VMRunnerIO(["python", "neo-python-VM.py", str(args.depth)])
    fuzzer.vm2 = VMRunnerIO(
        ["mono", "./neo-vm/src/neo-vm/bin/Debug/net461/Neo.VM.exe", str(args.depth)]
    )
    fuzzer.clean_exit_opcode = 0x66

    fuzzer.fuzz()
