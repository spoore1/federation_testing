#!/bin/bash

set -x 
set -e

MAJOR_VER=0
if [ -f /etc/os-release ]; then
    source /etc/os-release
    MAJOR_VER=${VERSION_ID%.*}
fi

echo "First running mod_auth_mellon tests"
./test_mellon.sh

if [ $MAJOR_VER -ne 8 ]; then
    echo "Next run lasso sha1 test."
    python3 test-lasso-sha1.py
fi
