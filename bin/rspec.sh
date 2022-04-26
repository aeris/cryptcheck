#!/usr/bin/env bash
set -e
eval "$(bin/load-rbenv "$1")"
BASE_DIR="$(dirname "$(dirname "$0")")"
shift
LD_PRELOAD="$BASE_DIR/build/libfake.so" LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$BASE_DIR/build/" \
  exec rspec "$@"
