#!/usr/bin/env python3
import random
import secrets
import sys
import struct
import ast
import os
from logzero import logger

from multiprocessing import Queue, Process


WORDS = [
    "e",
    "AA",
    "iwa",
    "epee",
    "abate",
    "reject",
    "satiric",
    "uxorious",
    "shibuichi",
    "headwaiter",
    "turncoatism",
    "pyroglutamic",
    "puebloization",
    "atlantomastoid",
    "inconsecutively",
    "hypercarburetted",
    "unsympathetically",
    "physiotherapeutics",
    "stereochromatically",
    "pneumohydropericardium",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
]

NAMES = list("abcdefghijklmnopqrstuvwxyz")


class SCRVal:
    pass


class SCString(SCRVal):
    def __init__(self, state):
        self.state = state

    def give_val(self, depth=0):
        word = random.choice(WORDS)
        return '"{}"'.format(word)


class SCNone(SCRVal):
    def __init__(self, state):
        self.state = state

    def give_val(self, depth=0):
        return "None"


class SCDict(SCRVal):
    def __init__(self, state):
        self.state = state
        self.used_keys = []

    def give_val(self, depth=0):
        choice = random.randint(0, 100)
        dict_kv_n = 0
        if choice == 0 or depth > 1:
            return "{}"
        elif choice >= 1 and choice < 99:
            dict_kv_n = random.randint(0, 5)
        elif choice == 99:
            dict_kv_n = random.randint(0, 1024)
        generated_dict = []

        for _ in range(0, dict_kv_n):
            key = random.choice(self.state.simple_types).give_val(depth + 1)
            val = self.state.scvalue.give_val(depth + 1)
            if not key in self.used_keys:
                self.used_keys.append(key)
            generated_dict.append("{}: {}".format(key, val))
        return "{{{}}}".format(",".join(generated_dict))

    def gen_access(self):
        if len(self.used_keys) > 0:
            return "[{}]".format(random.choice(self.used_keys))
        else:
            return ""


class SCList(SCRVal):
    def __init__(self, state):
        self.state = state
        self.val_generators = [
            self.state.scvalue,
            self.state.scvariable,
            # ----
            self.state.scinteger,
            self.state.scstring,
            self.state.scboolean,
            self.state.scnone,
        ]

    def give_val(self, depth=0):
        choice = random.randint(0, 100)
        list_len = 0
        if choice == 0 or depth > self.state.depth:
            return "[]"
        elif choice >= 1 and choice < 99:
            list_len = random.randint(0, 5)
        elif choice == 99:
            list_len = random.randint(0, 1024)
        generated_list = []
        val_generator = random.choice(self.val_generators)
        for _ in range(0, list_len):
            generated_list.append(val_generator.give_val(depth + 1))
        return "[{}]".format(",".join(generated_list))

    def gen_access(self):
        # [0] [:1] [1:] [1:1] [:]
        choice = random.randint(0, 4)
        if choice == 0:
            return "[{}]".format(self.state.scinteger.give_val())
        if choice == 1:
            return "[:{}]".format(self.state.scinteger.give_val())
        if choice == 2:
            return "[{}:]".format(self.state.scinteger.give_val())
        if choice == 3:
            return "[{}:{}]".format(
                self.state.scinteger.give_val(), self.state.scinteger.give_val()
            )
        if choice == 4:
            return "[:{}:{}]".format(
                self.state.scinteger.give_val(), self.state.scinteger.give_val()
            )
        if choice == 5:
            return "[{}::{}]".format(
                self.state.scinteger.give_val(), self.state.scinteger.give_val()
            )
        if choice == 6:
            return "[{}:{}:{}]".format(
                self.state.scinteger.give_val(),
                self.state.scinteger.give_val(),
                self.state.scinteger.give_val(),
            )


class SCBoolean(SCRVal):
    def __init__(self, state):
        self.state = state

    def give_val(self, depth=0):
        word = random.choice(["True", "False"])
        return "{}".format(word)


class SCInteger(SCRVal):
    def __init__(self, state):
        self.state = state
        MAX = sys.maxsize
        self.special_int = [
            MAX,
            MAX + 1,
            MAX - 1,
            -MAX - 1,
            -MAX,
            -MAX - 2,
            0,
            1,
            -1,
            2,
            -2,
            3,
            -3,
            1024,
            -1024,
            1025,
            -1025,
            4096,
            -4096,
            0xFF,
            0xFFFF,
            0xFFFFFF,
            0xFFFFFFFF,
            0x80,
            0x8000,
            0x800000,
            0x80000000,
            0x7F,
            0x7FFF,
            0x7FFFFF,
            0x7FFFFFFF,
        ]

    def give_val(self, depth=0):
        choice = random.randint(0, 10)
        integer = 0
        if choice == 0:
            integer = random.randint(min(self.special_int), max(self.special_int))
        elif choice == 1:
            integer = random.choice(self.special_int)
        elif choice >= 2:
            integer = random.randint(-0xFF, 0xFF)
        return "{}".format(integer)


"""
class SCFloat(SCRVal):
    def __init__(self, state):
        self.state = state
        CLOSE_MAX = 1.7976e308  # not the actual max but close enough
        MAX = sys.float_info.max
        MIN = sys.float_info.min
        self.special_val = [
            MAX,
            MAX * MIN,
            CLOSE_MAX,
            -CLOSE_MAX,
            MAX + 1.0e303,  #  inf
            MAX * -2,  # -inf
            -MAX,
            MAX - MAX,  # 0.0
            -0.0,
            0.0,
            MIN,
            -MIN,
            MAX + MIN,
            -MAX - MIN,
            1 / 3,
            -1 / 3,
        ]  # type: List[float]

    def give_val(self, depth=0):
        choice = random.randint(0, 10)
        val = 0.0
        if choice == 0:
            val = random.choice(self.special_val)
        elif choice == 1:
            val = float(int(random.randint(-10, 10)))
        elif choice < 6:
            f1 = float(int(random.randint(-10, 10)))
            f2 = float(int(random.randint(-10, 10)))
            if f2 == 0.0:
                f2 = 100.0
            val = f1 / f2
        elif choice >= 2:
            val = struct.unpack(
                "d", bytes([random.randint(0x000, 0xFF) for x in range(8)])
            )[0]
        return "{}".format(val), SCFloat
"""

# ------------------------------------------------


class SCValue:
    def __init__(self, state):
        self.state = state

    def give_val(self, depth=0):
        vals = self.state.all_types + [self.state.scvariable]
        return random.choice(vals).give_val(depth + 1)


class SCVariable:
    def __init__(self, state):
        self.state = state
        self.used_vars = []

    def give_val(self, depth=0):
        if len(self.used_vars) == 0:
            return self.state.scvalue.give_val(depth + 1)
        else:
            return random.choice(self.used_vars)

    def new_var(self):
        var_name = random.choice(NAMES)
        if not var_name in self.used_vars:
            self.used_vars.append(var_name)
        return var_name

    def gen(self, depth=0):
        var_value = self.state.scvalue.give_val(depth + 1)
        var_name = self.new_var()
        return "{} = {}".format(var_name, var_value)


# ------------------------------------------------


class SCOperator:
    def __init__(self, state):
        self.state = state
        self.a_boc = [
            "+",
            "/",
            "//",
            "&",
            "^",
            "|",
            # "**", # Op Not Converted BINARY_POWER
            "is",
            "is not",
            "<<",
            "%",
            "*",
            "-",
            ">>",
            ">",
            "<",
            "==",
            ">=",
            "<=",
            "!=",
            "in",
        ]
        self.ao_b = ["+", "*", "/", "//", "-", "%", "&", "^", "|"]
        self.a_ob = [
            # "+", # Op Not Converted UNARY_POSITIVE
            "-",
            "not",
            "~",
        ]
        self.access_generators = [self.state.sclist, self.state.scdict]
        self.oa = ["return"]
        self.special = ["pass"]  # added based on context

    def gen(self, depth=0):
        choice = random.randint(0, 4)
        if len(self.special) > 0:
            choice = random.randint(0, 5)
        if choice == 0:
            A = self.state.scvariable.give_val()
            B = self.state.scvariable.give_val()
            C = self.state.scvariable.give_val()

            if random.randint(0, 1) == 0:
                A = self.state.scvariable.new_var()
            return "{} = {} {} {}".format(A, B, random.choice(self.a_boc), C)
        elif choice == 1:
            A = self.state.scvariable.give_val()
            B = self.state.scvariable.give_val()
            return "{} {}= {}".format(A, random.choice(self.ao_b), B)
        elif choice == 2:
            A = self.state.scvariable.give_val()
            B = self.state.scvariable.give_val()
            return "{} = {} {}".format(A, random.choice(self.a_ob), B)
        elif choice == 3:  # return
            A = self.state.scvariable.give_val()
            if random.randint(0, 100) < 90:
                # Too many returns happening. TODO: Fix this nicer.
                return self.gen(depth)
            return "return ({},{})".format(random.randint(000000, 999999), A)
        elif choice == 4:
            A = self.state.scvariable.give_val()
            if random.randint(0, 1) == 0:
                A = self.state.scvariable.new_var()
            B = self.state.scvariable.give_val()
            return "{} = {}{}".format(
                A, B, random.choice(self.access_generators).gen_access()
            )
        elif choice == 5:  # only with special ops
            return random.choice(self.special)


# ------------------------------------------------


class SCState:
    def __init__(self, seed=None):

        self.depth = 5
        self.scvariable = SCVariable(self)
        self.scvalue = SCValue(self)

        self.scstring = SCString(self)
        self.scinteger = SCInteger(self)
        self.scboolean = SCBoolean(self)
        self.scnone = SCNone(self)
        if seed:
            # logger.info("set seed: {}".format(seed))
            random.seed(seed)
        # NEO doesn't do this.
        # self.scfloat = SCFloat(self)

        self.sclist = SCList(self)
        self.scdict = SCDict(self)

        self.scoperator = SCOperator(self)
        self.scconditional = SCConditional(self)

        self.simple_types = [self.scstring, self.scinteger, self.scboolean, self.scnone]
        self.complex_types = [self.sclist, self.scdict]
        self.all_types = self.simple_types + self.complex_types


class SCConditional:
    def __init__(self, state):
        self.state = state

    def gen(self, depth=0):
        # if, if else, if elif else, while
        if depth > 3:
            return ""
        choice = random.randint(0, 5)
        codeblock = SCCodeblock()

        codeblock.state.scoperator.special = self.state.scoperator.special[:]
        for var in self.state.scvariable.used_vars:
            if var not in codeblock.state.scvariable.used_vars:
                codeblock.state.scvariable.used_vars.append(var)

        if choice == 0:
            A = self.state.scvariable.give_val()
            B = self.state.scvariable.give_val()

            return "if {} {} {}:\n{}".format(
                A, random.choice(self.state.scoperator.a_boc), B, codeblock.gen(depth)
            )
        elif choice == 1:
            A = self.state.scvariable.give_val()
            B = self.state.scvariable.give_val()
            C = self.state.scvariable.give_val()
            D = self.state.scvariable.give_val()

            return "if {} {} {}:\n{}\n{}elif {} {} {}:\n{}".format(
                A,
                random.choice(self.state.scoperator.a_boc),
                B,
                codeblock.gen(depth),
                "    " * (depth - 1),
                C,
                random.choice(self.state.scoperator.a_boc),
                D,
                codeblock.gen(depth),
            )
        elif choice == 2:
            A = self.state.scvariable.give_val()
            B = self.state.scvariable.give_val()

            return "if {} {} {}:\n{}\n{}else:\n{}".format(
                A,
                random.choice(self.state.scoperator.a_boc),
                B,
                codeblock.gen(depth),
                "    " * (depth - 1),
                codeblock.gen(depth),
            )
        elif choice == 3:
            A = self.state.scvariable.give_val()
            B = self.state.scvariable.give_val()
            codeblock.state.scoperator.special += ["continue", "break"]

            return (
                "count{depth} = 0\n"
                "{space}while ({A} {OP} {B}) and count{depth} < 100:\n"
                "{space}    count{depth} += 1\n"
                "{block}".format(
                    depth=depth,
                    space=" " * (depth * 4 - 4),
                    A=A,
                    OP=random.choice(self.state.scoperator.a_boc),
                    B=B,
                    block=codeblock.gen(depth),
                )
            )
        elif choice == 4:
            A = self.state.scvariable.give_val()
            B = self.state.scvariable.give_val()
            codeblock.state.scoperator.special += ["continue", "break"]

            return "for {A} in {B}:\n" "{block}".format(
                depth=depth,
                space=" " * (depth * 4 - 4),
                A=A,
                B=B,
                block=codeblock.gen(depth),
            )
        elif choice == 5:
            A = self.state.scvariable.give_val()
            codeblock.state.scoperator.special += ["continue", "break"]

            return (
                "count{depth} = 0\n"
                "{space}while ({A}) and count{depth} < 100:\n"
                "{space}    count{depth} += 1\n"
                "{block}".format(
                    depth=depth,
                    space=" " * (depth * 4 - 4),
                    A=A,
                    block=codeblock.gen(depth),
                )
            )


class SCCodeblock:
    def __init__(self):
        self.state = SCState()

    def gen(self, depth=0):
        declarations = []
        num_vars = random.randint(1, 4)
        for _ in range(0, num_vars):
            declarations.append(self.state.scvariable.gen(depth + 1))
        num_ops = random.randint(0, 4)

        code = []
        for _ in range(0, num_ops):
            code.append(self.state.scoperator.gen(depth + 1))

        num_conds = 2
        for _ in range(0, num_conds):
            code.append(self.state.scconditional.gen(depth + 1))

        random.shuffle(code)
        ret = self.state.scvariable.give_val()
        if random.randint(0, 100) > 40:
            code.append("return [{}, {}]".format(random.randint(000000, 999999), ret))
        prefix = "    " * depth
        return "{}".format("\n".join([prefix + x for x in declarations + code]))


def _t_try_code(q: Queue, code: str):
    try:
        exec(code)
        q.put("Works")
    except Exception as e:
        q.put(e)


def timed_exec(code, timeout=1):
    q = Queue(1)
    p = Process(target=_t_try_code, args=(q, code), daemon=True)
    p.start()
    try:
        res = q.get(timeout=timeout)
    except Exception as ex:
        p._stop()
        raise TimeoutError("The code timed out after {} ({})".format(timeout, ex))
    if isinstance(res, Exception):
        raise res


class SCGenContract:
    def __init__(self, target="py"):
        self.target = target
        pass

    def gen(self, depth=0):
        codeblock = SCCodeblock()
        generated_code = codeblock.gen(depth + 1)
        if self.target == "py":
            return "def Main():\n{}\n\nMain()\n".format(generated_code)
        elif self.target == "sc" or self.target == "plain":  # for now the same
            return "def Main():\n{}\n".format(generated_code)
        else:
            raise ValueError("Unknown target {}".format(self.target))

    def gen_valid(self, mayblock=False):
        tries = 0
        while True:
            code = self.gen()
            try:
                # check for validity. We'll spawn a process if we're not allowe to block
                if mayblock:
                    exec(code)
                else:
                    timed_exec(code)
                return code, tries
            except KeyboardInterrupt:
                print(code)
                print("#>> bye")
                raise
            except Exception as ex:
                tries += 1
                pass


def run(
    seed=None, illegal=False, target="py", mayblock=False, verbose=False, evalcode=False
):
    if seed == None:
        seed = secrets.randbelow(1 << 32)
    if seed:
        # logger.info("seed: {}".format(seed))
        random.seed(seed)

    state = SCState(seed=seed)
    contract = SCGenContract(target=target)

    code = None
    if illegal:
        # Just return the first fit. Yolo.
        code = contract.gen()
        # print(code)
    else:
        code, tries = contract.gen_valid(mayblock=mayblock)
        # print(code)
        if verbose:
            print("# Generated {} illegal code blocks before one worked.".format(tries))

    if evalcode:
        # print("result = ", end="")
        sys.stdout.flush()
        os.system("/usr/bin/env python3 -c '{}'".format(code))

    return "# Seed was {}\n\n{}".format(seed, code)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", "-s", default=None, type=int, help="The initial seed")
    parser.add_argument(
        "--evalcode",
        "-e",
        action="store_true",
        help="Evals the code after creation, prints result",
    )
    parser.add_argument(
        "--target",
        "-t",
        default="py",
        type=str,
        choices=["py", "sc", "plain"],
        help="Output formatted for as NEO smart contract or regular CPython script.",
    )
    parser.add_argument(
        "--illegal",
        "-i",
        action="store_true",
        help="Do not loop to find valid code, output first generation.",
    )
    parser.add_argument(
        "--mayblock",
        "-m",
        action="store_true",
        help=(
            "Allow functions that soft-block (like large exponents).\n"
            "This means that the generation may never finish.\n"
            "However, code generation is quite a bit faster."
        ),
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )
    args = parser.parse_args()
    if args.illegal and args.mayblock:
        raise ValueError("Options: '--mayblock' has no effect if '--illegal' is set.")

    code = run(
        seed=args.seed,
        illegal=args.illegal,
        target=args.target,
        mayblock=args.mayblock,
        verbose=args.verbose,
        evalcode=args.evalcode,
    )
    print(code)
