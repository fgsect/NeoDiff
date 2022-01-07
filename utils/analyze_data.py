#!/usr/bin/env python3
import os

NAMES = [
    "../RESULTS/A_20p2000"
]  # 'a20p2000'] #'2k20o1p', '2k20o20p', '2k500o1p', '2k500o20p']

DATA = [
    "execs",
    "diffs",
    "diffs_new",
    "execs_per_sec",
    "diffs_new_opcode",
    "time",
    "typehashes",
    "typehashes_new",
]
# DATA = ['OPCODE_DIFFS']
RESULTS = {}
for name in NAMES:
    d = {}
    RESULTS[name] = {}
    for data in DATA:
        data_lengths = []
        _data = data
        with open("{}/stats_{}".format(name, _data)) as f:
            d[data] = f.readlines()
            data_lengths.append(len(d[data]))

    length = min(data_lengths)
    execs_accum = 0
    for i in range(0, length):
        execs_accum = int(d["execs"][i])
        RESULTS[name][execs_accum] = {}
        for data in DATA:
            RESULTS[name][execs_accum][data] = d[data][i]

for data in DATA:
    try:
        os.mkdir("_CSV")
    except Exception as ex:
        pass
        # print("Folder _CSV existed. This is fine.", ex)

    with open("_CSV/{}.csv".format(data), "w") as f:
        execs_accum = []
        for name in NAMES:
            execs_accum += list(RESULTS[name].keys())
        execs_accum.sort()

        vals_accum = {}
        vals = ["Execs"]
        for name in NAMES:
            vals.append(name.split("/")[-1])
        f.write("{}\n".format(",".join(vals)))
        for key in execs_accum:
            vals = [str(key)]
            for name in NAMES:
                if name not in vals_accum:
                    vals_accum[name] = 0

                val = RESULTS[name].get(key, None)
                if val:
                    vals_accum[name] = int(float(RESULTS[name][key][data].strip()))
                    # vals_accum[name] += int(float(RESULTS[name][key][data].strip()))
                    vals.append(str(vals_accum[name]))
                else:
                    vals.append("")
            print(vals)
            f.write("{}\n".format(",".join(vals)))
