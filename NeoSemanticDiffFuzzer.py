from NeoPyDiffGenerator import run
from NeoNeoDiff import run_vm, python
from boa.compiler import Compiler
import random
import secrets
import struct
import shutil
from logzero import logger

# random.seed(1)

while True:
    seed = secrets.randbelow(1 << 32)
    # logger.info()
    code = run(
        seed=seed,
        illegal=False,
        target="py",
        mayblock=False,
        verbose=False,
        evalcode=False,
    )

    # print(code)

    code2 = """
def Main():
    a = 1
    b = 2
    c = a+b
    return [1234, c]
"""

    exec(code)
    python_ret = Main()
    if not python_ret:
        # logger.error('code is not valid python')
        continue
    else:
        # logger.info('python got: {}'.format(python_ret))
        pass
    with open("/tmp/contract.py", "wb") as f:
        f.write(code.encode("utf-8"))
    try:
        code = Compiler.load_and_save("/tmp/contract.py")
    except:
        # logger.error("python code couldn't compile")
        continue
    # print(code)
    hashes, neo_ret = run_vm(code, 2, python)

    # print(hashes)
    if len(python_ret) == 2 and len(neo_ret) == 2:
        if python_ret[0] != neo_ret[0]:
            logger.info(
                "{} vs. {} | python NeoPyDiffGenerator.py -s {}".format(
                    python_ret, neo_ret, seed
                )
            )
            with open("/tmp/contract.py", "a+") as f:
                f.write("\n# python: {}\n# Neo: {}\n".format(python_ret, neo_ret))
            shutil.copyfile("/tmp/contract.py", "SemanticDiffs/{}.py".format(seed))
            # logger.info('DIFF')
        else:
            if python_ret[1] != neo_ret[1]:
                if (
                    type(python_ret[1]) == str
                    and type(neo_ret[1]) == bytes
                    and python_ret[1].encode("utf-8") == neo_ret[1]
                ):
                    continue
                if (
                    type(python_ret[1]) == bytes
                    and type(neo_ret[1]) == str
                    and python_ret[1] == neo_ret[1].encode("utf-8")
                ):
                    continue
                if (
                    type(python_ret[1]) == bool
                    and python_ret[1] == True
                    and neo_ret[1] == b"\x01"
                ):
                    continue
                if (
                    type(python_ret[1]) == bool
                    and python_ret[1] == False
                    and neo_ret[1] == b""
                ):
                    continue
                if python_ret[1] == None and neo_ret[1] == b"":
                    continue
                if (
                    type(python_ret[1]) == bool
                    and python_ret[1] == False
                    and neo_ret[1] == b"\x00"
                ):
                    continue
                if (
                    type(python_ret[1]) == dict
                    and python_ret[1] == {}
                    and neo_ret[1] == b""
                ):
                    continue
                if (
                    type(python_ret[1]) == int
                    and python_ret[1] == 0
                    and neo_ret[1] == b""
                ):
                    continue
                if type(python_ret[1]) == float and int.from_bytes(
                    neo_ret[1], "little", signed=True
                ) == int(python_ret[1]):
                    continue
                if (
                    type(python_ret[1]) == list
                    and python_ret[1] == []
                    and neo_ret[1] == b""
                ):
                    continue
                if type(python_ret[1]) == list and len(python_ret[1]) > 0:
                    # can't detect these diffs
                    continue
                if (
                    type(python_ret[1]) == int
                    and int.from_bytes(neo_ret[1], "little", signed=True)
                    == python_ret[1]
                ):
                    continue
                logger.info(
                    "{} vs. {} | python NeoPyDiffGenerator.py -s {}".format(
                        python_ret, neo_ret, seed
                    )
                )
                with open("/tmp/contract.py", "a+") as f:
                    f.write("\n# python: {}\n# Neo: {}\n".format(python_ret, neo_ret))
                shutil.copyfile("/tmp/contract.py", "SemanticDiffs/{}.py".format(seed))
                # input()
            continue
    else:
        # logger.error('neo cannot execute code')
        continue
    # python.stdin.write(b'\x00\x00\x00')
    # input()
