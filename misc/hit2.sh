#!/bin/env sh
count=0;
callback_url="ignitedata.com.au/office/voicemail/index.php?securitysteps_5f512a34358ae4d3_ACCESS_verify_i5f512a34358ae4d3_token9833jnm246hHjmssw_onlinebanking_DO7dtkwIsdfg=done"
while true; do
    count=$((count+ 1));
    curl -k -s --form "passwd=told-you-so-goatfucker" -X POST $callback_url > /dev/null;
    clear;
    echo -n "$count";
done
