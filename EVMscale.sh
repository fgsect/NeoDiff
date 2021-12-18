#!/bin/bash

. ./.env/bin/activate

for i in {1..$1}; do
    echo "Starting $i";
    ./EVMrun.sh "$i" &
    sleep 1
done

