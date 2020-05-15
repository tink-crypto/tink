#!/bin/bash

set -euo pipefail
cd ${KOKORO_ARTIFACTS_DIR}/git/tink

export XCODE_VERSION=11.3
export DEVELOPER_DIR="/Applications/Xcode_${XCODE_VERSION}.app/Contents/Developer"
export ANDROID_HOME="/Users/kbuilder/Library/Android/sdk"

cd apps
use_bazel.sh $(cat .bazelversion)
time bazel build -- ...
time bazel test -- ...
