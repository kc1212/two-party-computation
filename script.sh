#!/usr/bin/env bash

set -e
set -u
set -x

res="results.txt"
echo -n "" > "$res"

for i in $(seq 5 5 30); do
    for j in $(seq 5); do # repeat 5 times to average
        echo -n "$i," >> "$res"
        java com.twopc.Main "$i" | head -n 4 | sed 's/^.*:\s*//g' | paste -d, - - - - >> "$res"
    done
done
