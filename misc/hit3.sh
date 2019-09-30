#!/bin/env sh
count=0;
callback_url="https://mail.epsilon-media.com/wp-content/dhl/DHL AUTO/verify.php"
while true; do
    count=$((count+ 1));
    curl -k -s --form "email=tired?_contact_me&epass=spam.email.from.god@gmail.com" -X POST $callback_url > /dev/null;
    clear;
    echo -n "$count";
done
