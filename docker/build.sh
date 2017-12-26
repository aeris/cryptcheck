#!/bin/bash

set -eux

export CC_HOME=/home/cryptcheck
adduser -h $CC_HOME -u 1000 -s /bin/sh -D cryptcheck

apk update
apk add su-exec ca-certificates openssl coreutils
apk add --virtual .build-deps make su-exec git g++ patch perl curl zlib-dev libffi-dev linux-headers readline-dev

cd $CC_HOME
su - cryptcheck -c 'make clean mr-proper build/'
su - cryptcheck -c "bash $CC_HOME/docker/install_ruby.sh"

apk del .build-deps
rm -rf $CC_HOME/build