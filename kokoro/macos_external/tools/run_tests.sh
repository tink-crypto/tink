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

export XCODE_VERSION="14.1"
export DEVELOPER_DIR="/Applications/Xcode.app/Contents/Developer"
export ANDROID_HOME="/usr/local/share/android-sdk"
export COURSIER_OPTS="-Djava.net.preferIPv6Addresses=true"

IS_KOKORO="false"
if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]]; then
  IS_KOKORO="true"
fi
readonly IS_KOKORO

if [[ "${IS_KOKORO}" == "true" ]] ; then
  cd "$(echo "${KOKORO_ARTIFACTS_DIR}"/git*/tink)"
  export JAVA_HOME=$(/usr/libexec/java_home -v "1.8.0_292")
fi

./kokoro/testutils/copy_credentials.sh "tools/testdata" "all"
./kokoro/testutils/update_android_sdk.sh
# Sourcing required to update callers environment.
source ./kokoro/testutils/install_go.sh
echo "Using go binary from $(which go): $(go version)"

# TODO(b/155225382): Avoid modifying the sytem Python installation.
pip3 install --user protobuf

# Run manual tests which rely on key material injected into the Kokoro
# environement.
MANUAL_TARGETS=()
if [[ "${IS_KOKORO}" == "true" ]] ; then
  MANUAL_TARGETS+=(
    "//tinkey/src/test/java/com/google/crypto/tink/tinkey:CreateKeysetCommandTest"
    "//tinkey/src/test/java/com/google/crypto/tink/tinkey:CreatePublicKeysetCommandTest"
    "//tinkey/src/test/java/com/google/crypto/tink/tinkey:RotateKeysetCommandTest"
  )
fi
readonly MANUAL_TARGETS

./kokoro/testutils/run_bazel_tests.sh tools "${MANUAL_TARGETS}"
