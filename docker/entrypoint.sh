#!/bin/bash

set -eu

source ~/.bash_profile

if [ "$1" == "dev" ]; then
    echo "Container started, waiting for you to connect. Execute:\n$ docker exec -it <container_name> bash)"
    tail -f /dev/null
    exit 0
fi

if [ -f ~/bin/$1 ]; then
    ACTION=$1
    shift
    ~/bin/$ACTION $@
fi