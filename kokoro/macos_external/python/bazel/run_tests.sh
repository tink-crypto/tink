#!/bin/bash

set -euo pipefail
cd ${KOKORO_ARTIFACTS_DIR}/git/tink

# Install protobuf pip packages
pip3 install protobuf --user

run_bazel_tests() {
  (
    cd python
    use_bazel.sh $(cat .bazelversion)

    time bazel build -- ...
    time bazel test --test_output=errors -- ...
  )
}

run_bazel_tests
