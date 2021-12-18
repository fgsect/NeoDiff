import os
import subprocess
import sys
import random
import struct
import neo

# code = os.urandom(0xfff).hex()


# print(createSyscall())
def fuzz(once=False):
    last_tell = 0
    running = True
    out1, out2 = "", ""
    good_code = ""
    i = 0
    with open("good_code", "a+") as f:
        while running:
            code = createCode().hex()[:20]
            p1 = subprocess.Popen(
                ["python3", "main.py", code],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # print(out1)
            # print("\n")
            p2 = subprocess.Popen(
                [
                    "dotnet",
                    "/Users/fabian/projects/neofuzzcs/neofuzzcs/bin/Debug/netcoreapp2.1/neofuzzcs.dll",
                    code,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            out1, err1 = p1.communicate()
            out2, err2 = p2.communicate()

            sys.stdout.write("\rRUN: {} ({})".format(i, len(known_ops)))
            sys.stdout.flush()
            l = min(len(out1), len(out2))
            if out1[:l] != out2[:l]:
                # if b"ADD1" in out1 or b"ADD2" in out1:
                running = False
            i += 1
            out1l = out1.splitlines()
            out2l = out2.splitlines()
            l = min(len(out1l), len(out2l))
            k = 0
            lastop = "XX"
            uneq = ""
            ops = []
            uneq_i = 0
            while k < l:
                if out1l[k] != out2l[k]:
                    uneq = "{} != {}".format(out1l[k], out2l[k])
                    uneq_i = k
                    running = False
                    if len(ops) > 0:
                        lastop = ops[-1]
                # print(out1l[k])
                if out1l[k].startswith(b"OP,"):

                    ops.append(out1l[k][3:].decode("ascii"))
                if b". peek: " in out1l[k]:
                    last_tell = int(out1l[k].split(b"peek:")[1].strip())
                k += 1
            if len(ops) > 1:
                ops.pop()
            if last_tell > 0:
                good_code = code[: last_tell * 2]
                good_ops = ",".join(ops)
                if len(good_ops) < 4 and good_ops not in known_ops:
                    known_ops.add(good_ops)
                    known_code[good_ops] = good_code
                    f.write("{};{}\n".format(good_ops, good_code))
            if once:
                running = False

    out = ""
    out += "\n"
    out += "code: " + good_code + "\n"
    out += "[*] PYTHON:\n"
    out += (b"\n".join(out1l[:uneq_i]).decode("ascii")) + "\n"
    out += ("[x] {}".format(uneq)) + "\n"
    out += (b"\n".join(out1l[uneq_i:]).decode("ascii")) + "\n"
    out += "\n[!] PYTHON Errors:\n"
    out += (err1.decode("ascii")) + "\n"
    out += ("\n\n[*] CSHARP:") + "\n"
    out += (b"\n".join(out2l[:uneq_i]).decode("ascii")) + "\n"
    out += ("[x] {}".format(uneq)) + "\n"
    out += (b"\n".join(out2l[uneq_i:]).decode("ascii")) + "\n"
    out += ("\n[!] CSHARP Errors:\n") + "\n"
    out += (err2.decode("ascii")) + "\n"

    # print(out)
    out += "last OP: {}\n".format(lastop)
    out += "last peak: {}\n".format(last_tell)

    return lastop, uneq, out, good_code


if len(sys.argv) > 1:
    if sys.argv[1] == "once":
        lastop, uneq, out, good_code = fuzz(once=True)
        print(out)
    else:
        lastop, uneq, out, good_code = fuzz()
        print(out)
    exit(0)

while True:
    lastop, uneq, out, last_tell = fuzz()
    reason = ""
    for c in uneq:
        if not c.isalnum():
            reason += "_"
        else:
            reason += c
    fname = "cases5/{}_{}_{}_{}".format(
        lastop,
        neo.ToName(int(lastop, 16)),
        reason[:64],
        random.randint(11111111, 99999999),
    )
    print("\n{}".format(fname))
    with open(fname, "wb") as f:
        f.write(out.encode("ascii"))
