#!/bin/bash

set -euo pipefail
cd ${KOKORO_ARTIFACTS_DIR}/git/tink

./kokoro/copy_credentials.sh

cd cc

# TODO(b/140615798): Run all tests once fixed.

use_bazel.sh $(cat .bazelversion)
bazel build -- ... -//integration/gcpkms/...
bazel test -- ... -//integration/gcpkms/...
