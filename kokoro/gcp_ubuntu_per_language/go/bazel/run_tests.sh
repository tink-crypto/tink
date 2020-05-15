#!/bin/bash

set -euo pipefail

cd "${KOKORO_ARTIFACTS_DIR}/git/tink/go"
use_bazel.sh "$(cat .bazelversion)"
time bazel build -- ...
time bazel test -- ...
