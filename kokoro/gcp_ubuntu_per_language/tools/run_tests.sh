#!/bin/bash

set -euo pipefail
cd ${KOKORO_ARTIFACTS_DIR}/git/tink

./kokoro/copy_credentials.sh

cd tools
use_bazel.sh $(cat .bazelversion)
time bazel build -- ...
time bazel test --test_output=errors -- ...
