import random
import struct
import os
import binascii
from logzero import logger
import secrets
import json
from NeoPyDiffGenerator import SCInteger

# code = os.urandom(0xfff).hex()


def random_bytes(n):
    return bytes(random.getrandbits(8) for _ in range(n))


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
            c = random.randint(0, 4 + (probability) + (probability * 4))

            if c == 0:
                # random byte number for pushing bytes
                pushbytesOpcode = 0x60 + random.randint(0x00, 32)
                pushbytesData = random_bytes(pushbytesOpcode - (0x60 - 1))
                # logger.info(bytes([pushbytesOpcode]))
                code += bytes([pushbytesOpcode]) + pushbytesData
            elif c == 1:
                # PUSHBYTES4 random 4 or 8 byte integer push
                r = int(scinteger.give_val())
                try:
                    code += b"\x63" + struct.pack("i", r)
                except struct.error:
                    pass
                try:
                    code += b"\x67" + struct.pack("q", r)
                except struct.error:
                    pass
            elif c == 2:
                # create completly random byte sequence
                code += random_bytes(random.randint(0x1, 0xF))
            elif c >= 3 and c <= 3 + (
                probability
            ):  # pick random code from all coverage
                d = random.randint(0, 2)
                if d == 0:
                    if len(all_coverage.keys()) > 0:
                        rand_state = random.choice(list(all_coverage.keys()))
                        rand_code = binascii.unhexlify(
                            random.choice(all_coverage[rand_state])["vm1_code"]
                        )
                        code += rand_code
                elif d == 1:
                    if len(all_coverage.keys()) > 0:
                        rand_state = random.choice(list(all_coverage.keys()))
                        rand_code = binascii.unhexlify(
                            all_coverage[rand_state][-1]["vm1_code"]
                        )
                        code += rand_code
                elif d == 2:
                    if len(all_coverage.keys()) > 0:
                        rand_state = random.choice(list(all_coverage.keys()))
                        rand_code = binascii.unhexlify(
                            all_coverage[rand_state][-1]["vm1_code"]
                        )
                        pos = random.randint(0, len(rand_code) - 1)
                        code += rand_code[:pos] + random_bytes(1) + rand_code[pos + 1 :]
            elif c >= 4 + (probability) and c <= 4 + (probability) + (
                probability * 4
            ):  # pick random from new coverage
                d = random.randint(0, 2)
                if d == 0:
                    if len(new_coverage.keys()) > 0:
                        rand_state = random.choice(list(new_coverage.keys()))
                        rand_code = binascii.unhexlify(
                            random.choice(new_coverage[rand_state])["vm1_code"]
                        )
                        code += rand_code
                elif d == 1:
                    if len(new_coverage.keys()) > 0:
                        rand_state = random.choice(list(new_coverage.keys()))
                        rand_code = binascii.unhexlify(
                            new_coverage[rand_state][-1]["vm1_code"]
                        )
                        code += rand_code
                elif d == 2:
                    if len(new_coverage.keys()) > 0:
                        rand_state = random.choice(list(new_coverage.keys()))
                        rand_code = binascii.unhexlify(
                            new_coverage[rand_state][-1]["vm1_code"]
                        )
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
