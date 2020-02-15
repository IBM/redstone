#!/bin/bash

# usage: test_cli.sh
# Set IBMCLOUD_API_KEY and KEY_CRNS to use

error() {
    [ -n "$1" ] && echo "$*" >&2
}

die() {
    error "$*"
    exit 1
}

cat setup.py | python -m redstone.crypto encrypt --key-crns "$KEY_CRNS" - | python -m redstone.crypto decrypt -
[ $? -eq 0 ] || die "test 1 failed"

RSCRYPTO_KEY_CRNS=$KEY_CRNS python -m redstone.crypto encrypt setup.py | python -m redstone.crypto decrypt -
[ $? -eq 0 ] || die "test 2 failed"

RSCRYPTO_KEY_CRNS=$KEY_CRNS python -m redstone.crypto encrypt setup.py > encrypted_file
[ $? -eq 0 ] || die "test 3 part 1 failed"
python -m redstone.crypto decrypt encrypted_file
[ $? -eq 0 ] || die "test 3 part 2  failed"

rm -f encrypted_file
