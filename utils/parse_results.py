import ast
import struct


def parse(content: bytes) -> bytes:
    content = content.strip()
    csplit = content.split(b",", 1)
    current = csplit[0]
    if current.startswith(b"("):
        current = current[1:]
    if not len(current):
        return b""

    elif current.startswith(b"ByteArray"):
        vals = csplit[1].split(b",", 1)
        val = vals[0]
        if val.endswith(b")"):
            val = val[:-1]
        if not len(val):
            ret = b"''"
        else:
            ret = b"0x" + binascii.hexlify(binascii.unhexlify(val)[::-1])
        if len(vals) > 1:
            ret += b", " + parse(vals[1])
        return ret

    elif current.startswith(b"Integer"):
        vals = csplit[1].split(b",", 1)
        val = vals[0]
        ret = b""
        if val.endswith(b")"):
            val = val[:-1]
        if not len(val):
            ret += b"0"
        else:
            ret += val
        if len(vals) > 1:
            ret += b", " + parse(vals[1])

        return ret + b""

    elif current.startswith(b"Array"):
        ret = b"["

        arr = csplit[1].split(b"[", 1)[1].rsplit(b"]", 1)
        ret += parse(arr[0])
        if csplit[1] == b"[]":
            return b"[]"

        if len(arr) > 1:
            ret += b", " + parse(arr[1])
        return ret + b"]"

    elif current.startswith(b"Map"):
        ret = b"{}"
        vals = csplit[1].split(b",", 1)
        if len(vals) > 1:
            ret += b", " + parse(vals[1])
        return ret

    elif current.startswith(b"Boolean"):

        vals = csplit[1].split(b",", 1)
        if len(vals) > 1:
            ret += b", " + parse(vals[1])
        return vals[0]

    raise Exception(f"Not implemented: {content}")


def parse_initial(content: str):
    content = content.split(";", 1)
    ret = b"("
    part1 = ast.literal_eval(content[0])
    ret += parse(part1)
    ret += b","
    part2 = ast.literal_eval(content[1])
    ret += parse(part2)
    ret += b")"
    return ret


def semantic_diff(python, neo):
    python = python.strip()
    neo = neo.strip()
    BRANCH = False
    VALUE = False
    if python and python != "None" and ";" in neo and neo.startswith("b'ByteArray,"):
        # print("{} vs {}".format(python, neo))
        content = neo.split(";", 1)
        print(neo)
        part1 = ast.literal_eval(content[0])
        branch_neo = int(parse(part1), 16)
        part2 = ast.literal_eval(content[1])
        ret_neo = eval(parse(part2))

        branch_py, ret_py = eval(python)

        if branch_py != branch_neo:
            # print(branch_py, branch_neo)
            BRANCH = True
        else:
            if ret_py != ret_neo:

                VALUE = True
                if type(ret_py) == str and len(ret_py) == 1 and ord(ret_py) == ret_neo:
                    VALUE = False
                elif type(ret_py) == list and type(ret_neo) == list:
                    if len(ret_py) == len(ret_neo):
                        VALUE = False
                        for a, b in zip(ret_py, ret_neo):
                            if a == b:
                                continue
                            elif a == False and b == "":
                                continue
                            elif a == None and b == "":
                                continue
                            elif a == True and b == 1:
                                continue
                            VALUE = True
                elif type(ret_py) == bool and type(ret_neo) == int and ret_neo == 0:
                    VALUE = False
                elif type(ret_py) == bool and type(ret_neo) == str and not ret_neo:
                    VALUE = False
                elif ret_py == None and type(ret_neo) == str and not ret_neo:
                    VALUE = False
                elif type(ret_py) == str and type(ret_neo) == int:
                    h = hex(ret_neo)
                    if h.endswith("L"):
                        h = h[:-1]
                    if binascii.unhexlify(hex(ret_neo)[2:])[::-1] == ret_py.encode(
                        "ascii"
                    ):
                        VALUE = False
                elif type(ret_py) == int and ret_py < 0 and type(ret_neo) == int:

                    if len(hex(ret_neo)) == 6:
                        i = struct.unpack("h", struct.pack("H", ret_neo))[0]
                        if i == ret_py:
                            VALUE = False
                    elif len(hex(ret_neo)) == 4:
                        i = struct.unpack("b", struct.pack("B", ret_neo))[0]
                        if i == ret_py:
                            VALUE = False
                    elif len(hex(ret_neo)) == 10:
                        i = struct.unpack("i", struct.pack("I", ret_neo))[0]
                        if i == ret_py:
                            VALUE = False

    if VALUE:
        exit(0)
    return BRANCH, VALUE

    return BRANCH, VALUE


from logzero import logger
import binascii

lines = None
with open("ndpygen_runs.csv", "r") as f:
    lines = f.readlines()

vmdiffs = {}
vmdiff_count = 0
semantic_branch_python27_csharp = 0
semantic_branch_python37_csharp = 0
semantic_branch_python27_python = 0
semantic_branch_python37_python = 0

semantic_value_python27_csharp = 0
semantic_value_python37_csharp = 0
semantic_value_python27_python = 0
semantic_value_python37_python = 0
ignore = []
for line in lines:
    items = line.split("\t")
    # print(items)
    if len(items) != 32:
        logger.error("{}".format(items))
        exit(1)
    if items[17] == "diff":
        vmdiff_count += 1
        if items[18] not in vmdiffs:
            vmdiffs[items[18]] = 0
        vmdiffs[items[18]] += 1
        # print(items[17], items[18])
    if items[27] == "semanticdiff":

        python27 = items[28]
        python37 = items[29]
        csharp = items[30]
        python = items[31]

        try:
            if semantic_diff(python27, csharp)[0]:
                semantic_branch_python27_csharp += 1
            if semantic_diff(python37, csharp)[0]:
                semantic_branch_python37_csharp += 1
            if semantic_diff(python27, python)[0]:
                semantic_branch_python27_python += 1
            if semantic_diff(python37, python)[0]:
                semantic_branch_python37_python += 1

            if semantic_diff(python27, csharp)[1]:
                semantic_value_python27_csharp += 1
            if semantic_diff(python37, csharp)[1]:
                semantic_value_python37_csharp += 1
            if semantic_diff(python27, python)[1]:
                semantic_value_python27_python += 1
            if semantic_diff(python37, python)[1]:
                semantic_value_python37_python += 1
        except:
            ignore.append(line)

vmdiffs = {}
vmdiff_count = 0
semantic_branch_python27_csharp = 0
semantic_branch_python37_csharp = 0
semantic_branch_python27_python = 0
semantic_branch_python37_python = 0

semantic_value_python27_csharp = 0
semantic_value_python37_csharp = 0
semantic_value_python27_python = 0
semantic_value_python37_python = 0
ignored = 0
for line in lines[:22000]:
    if line in ignore:
        ignored += 1
        continue
    items = line.split("\t")
    # print(items)
    if len(items) != 32:
        logger.error("{}".format(items))
        exit(1)
    if items[17] == "diff":
        vmdiff_count += 1
        if items[18] not in vmdiffs:
            vmdiffs[items[18]] = 0
        vmdiffs[items[18]] += 1
        # print(items[17], items[18])
    if items[27] == "semanticdiff":

        python27 = items[28]
        python37 = items[29]
        csharp = items[30]
        python = items[31]

        if semantic_diff(python27, csharp)[0]:
            semantic_branch_python27_csharp += 1
        if semantic_diff(python37, csharp)[0]:
            semantic_branch_python37_csharp += 1
        if semantic_diff(python27, python)[0]:
            semantic_branch_python27_python += 1
        if semantic_diff(python37, python)[0]:
            semantic_branch_python37_python += 1

        if semantic_diff(python27, csharp)[1]:
            semantic_value_python27_csharp += 1
        if semantic_diff(python37, csharp)[1]:
            semantic_value_python37_csharp += 1
        if semantic_diff(python27, python)[1]:
            semantic_value_python27_python += 1
        if semantic_diff(python37, python)[1]:
            semantic_value_python37_python += 1


print("Amount of fuzzer rounds: {}".format(len(lines)))
print("ignored: {}".format(ignored))
print()
print(
    "VM Discrepancies: VM state is compared for each instruction, if the values on the stack diverge, we found a discrepancy"
)
print(" - Total discrepancies: {}".format(vmdiff_count))
print(" - Different Opcodes leading to VM Discrepancies: {}".format(len(vmdiffs)))
for op in vmdiffs:
    print("   + Differentials found with Opcode {}: {}".format(op[2:-1], vmdiffs[op]))
print()
print(
    "Semantic Differences: The returned value from the NeoVM execution is compared to CPython return values"
)

print("Different Branch")
print("Python2.7 vs. CSharp NeoVM: {}".format(semantic_branch_python27_csharp))
print("Python2.7 vs. Python NeoVM: {}".format(semantic_branch_python27_python))
print("Python3.7 vs. CSharp NeoVM: {}".format(semantic_branch_python37_csharp))
print("Python3.7 vs. Python NeoVM: {}".format(semantic_branch_python37_python))
print()
print("Same Branch but different Values")
print("Python2.7 vs. CSharp NeoVM: {}".format(semantic_value_python27_csharp))
print("Python2.7 vs. Python NeoVM: {}".format(semantic_value_python27_python))
print("Python3.7 vs. CSharp NeoVM: {}".format(semantic_value_python37_csharp))
print("Python3.7 vs. Python NeoVM: {}".format(semantic_value_python37_python))
