#!/bin/bash

set -euo pipefail
cd ${KOKORO_ARTIFACTS_DIR}/git/tink

./kokoro/copy_credentials.sh

cd tools

export XCODE_VERSION=11.3
export DEVELOPER_DIR="/Applications/Xcode_${XCODE_VERSION}.app/Contents/Developer"
export ANDROID_HOME="/Users/kbuilder/Library/Android/sdk"

# TODO(b/155225382): Avoid modifying the sytem Python installation.
pip3 install --user protobuf

use_bazel.sh $(cat .bazelversion)
time bazel build -- ...
time bazel test --test_output=errors -- ...
