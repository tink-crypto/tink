#!/bin/bash

set -euo pipefail
cd ${KOKORO_ARTIFACTS_DIR}/git/tink

cd objc
## TODO(b/155060426) Reenable once the tests work.
# use_bazel.sh $(cat .bazelversion)
# time bazel build -- ...
# time bazel test -- ...
