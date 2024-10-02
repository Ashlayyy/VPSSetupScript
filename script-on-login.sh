#!/bin/bash

String=test
NTFYTOKEN=TESTTOKEN
NTFYURL=TESTDOMAIN

curl -X PUT -d "\"$SSH_CONNECTION\" - \"$USER\" logged in on $HOSTNAME" $NTFYURL -H "Authorization: Bearer $NTFYTOKEN" -H "Priority: 4" -H "X-Tags: warning" -H "Title: $HOSTNAME -- SSH LOGIN" > /dev/null 2>&1

if [[ $SSH_ORIGINAL_COMMAND ]]; then
    eval "$SSH_ORIGINAL_COMMAND"
    exit
fi
/bin/bash