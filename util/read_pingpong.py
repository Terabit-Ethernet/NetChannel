import numpy as np
import sys
def read_file(filename):
    f = open(filename, "r")
    lines = f.readlines()
    result = []
    first_line = 0
    for line in lines:
        params = line.split()
        if len(params) < 3:
            continue
        if first_line < 100:
            first_line += 1
            continue
        latency = float(params[2])
        result.append(latency)
    return result


num_files = int(sys.argv[1])
method = (sys.argv[2])
result = []
for i in range(num_files):
    r = read_file("result_{}_pingpong_{}".format(method, i))
    for a in r:
        result.append(a)
    result.sort()
print("mean:", np.mean(result),"median:", np.percentile(result,50), "99: ", np.percentile(result, 99), "99.9: ", np.percentile(result, 99.9))
