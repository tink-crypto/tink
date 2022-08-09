#!/bin/bash
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################


set -euo pipefail


export XCODE_VERSION=11.3
export DEVELOPER_DIR="/Applications/Xcode_${XCODE_VERSION}.app/Contents/Developer"
export ANDROID_HOME="/Users/kbuilder/Library/Android/sdk"
export COURSIER_OPTS="-Djava.net.preferIPv6Addresses=true"

cd "${KOKORO_ARTIFACTS_DIR}/git/tink"
./kokoro/testutils/copy_credentials.sh "tools/testdata" "all"
./kokoro/testutils/update_android_sdk.sh
# Sourcing required to update callers environment.
source ./kokoro/testutils/install_go.sh

echo "Using go binary from $(which go): $(go version)"

# TODO(b/155225382): Avoid modifying the sytem Python installation.
pip3 install --user protobuf

cd tools
use_bazel.sh $(cat .bazelversion)

declare -a TEST_FLAGS
TEST_FLAGS=(
  --strategy=TestRunner=standalone
  --test_output=errors
  --jvmopt="-Djava.net.preferIPv6Addresses=true"
)
readonly TEST_FLAGS

time bazel build -- ...
time bazel test "${TEST_FLAGS[@]}" -- ...

# Run manual tests which rely on key material injected into the Kokoro
# environement.
if [[ -n "${KOKORO_ROOT}" ]]; then
  declare -a MANUAL_TARGETS
  MANUAL_TARGETS=(
    "//testing/cc:aws_kms_aead_test"
    "//testing/cc:gcp_kms_aead_test"
    "//testing/cross_language:aead_envelope_test"
    "//tinkey/src/test/java/com/google/crypto/tink/tinkey:AddKeyCommandTest"
    "//tinkey/src/test/java/com/google/crypto/tink/tinkey:CreateKeysetCommandTest"
    "//tinkey/src/test/java/com/google/crypto/tink/tinkey:CreatePublicKeysetCommandTest"
    "//tinkey/src/test/java/com/google/crypto/tink/tinkey:RotateKeysetCommandTest"
  )
  readonly MANUAL_TARGETS
  time bazel test "${TEST_FLAGS[@]}" -- "${MANUAL_TARGETS[@]}"
fi
