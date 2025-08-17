#!/bin/bash
# Wrapper script for running xtask commands

cd "$(dirname "$0")/xtask"
exec cargo run -- "$@"