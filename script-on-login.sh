#!/bin/bash
Domain="ntfy.ashlaydev.com"
curl 
    -d "\"$SSH_CONNECTION\" - \"$USER\" logged in" -L $Domain/loginNotifications >/dev/null 2>&1
if [[ $SSH_ORIGINAL_COMMAND ]]; then
    eval "$SSH_ORIGINAL_COMMAND"
    exit
fi
/bin/bash