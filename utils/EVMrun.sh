#!/bin/bash

# start EVMFuzz.py

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "SCRIPT_DIR"/..

set -x
# parameter is the seed
while :; do ./EVMFuzz.py --name A_20p2000 --seed "$1" --roundsize 2000 --probability 20; echo "Crashed! Restarting"; sleep 1 ; done

