#!/bin/bash

set -euo pipefail
cd ${KOKORO_ARTIFACTS_DIR}/git/tink

cd java_src
use_bazel.sh $(cat .bazelversion)
bazel build ...
bazel test ...
