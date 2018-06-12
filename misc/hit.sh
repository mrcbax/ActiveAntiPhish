#!/bin/env sh
count=0;
callback_url = ""
while true; do
    count=$((count+ 1));
    curl -k -s --form "userid=<randomusername>&pass=<randompass>" -X POST $callback_url > /dev/null;
    clear;
    echo -n "$count";
done
