#!/bin/bash

set -e

cd "$(dirname $0)"

cargo build --release --locked --config "build.rustflags=[\"--remap-path-prefix\", \"$HOME/.cargo=.cargo\", \"--remap-path-prefix\", \"$PWD=project\"]"
