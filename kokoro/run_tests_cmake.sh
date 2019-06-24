#!/bin/bash

set -e

cd git*/tink

echo "========================================================= Running cmake"
cmake --version
cmake . -DTINK_BUILD_TESTS=ON
echo "==================================================== Building with make"
make -j8 all
echo "===================================================== Testing with make"
CTEST_OUTPUT_ON_FAILURE=1 make test
echo "================================================ Done testing with make"

