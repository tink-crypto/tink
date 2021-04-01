#!/bin/bash

set -euo pipefail
cd ${KOKORO_ARTIFACTS_DIR}/git/tink

./kokoro/copy_credentials.sh

echo "========================================================= Running cmake"
cmake --version
cmake . cmake . -DTINK_BUILD_TESTS=ON -DCMAKE_CXX_STANDARD=11
echo "==================================================== Building with make"
make -j8 all
echo "===================================================== Testing with make"
CTEST_OUTPUT_ON_FAILURE=1 make test
echo "================================================ Done testing with make"

(
  export TEST_TMPDIR="$(mktemp -d)"
  export TEST_SRCDIR="$(cd ..; pwd)"
  cd examples/cc/helloworld
  ./cmake_build_test.sh
)
