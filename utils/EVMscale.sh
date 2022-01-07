#!/bin/bash

# Scale EVMFuzz.py to multiple cores

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "SCRIPT_DIR"

. ../.env/bin/activate

for i in {1..$1}; do
    echo "Starting $i";
    ./EVMrun.sh "$i" &
    sleep 1
done

