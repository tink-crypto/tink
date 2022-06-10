#!/bin/bash
# Copyright 2022 Google LLC
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

# The user may specify TINK_BASE_DIR for setting a local copy of Tink to use
# when running the script locally.

set -euo pipefail

# If we are running on Kokoro cd into the repository.
if [[ -n "${KOKORO_ROOT:-}" ]]; then
  cd "${KOKORO_ARTIFACTS_DIR}/git/tink_tinkey"
  use_bazel.sh "$(cat .bazelversion)"
fi

# Note: When running on the Kokoro CI, we expect these folders to exist:
#
#  ${KOKORO_ARTIFACTS_DIR}/git/tink_java
#  ${KOKORO_ARTIFACTS_DIR}/git/tink_java_awskms
#  ${KOKORO_ARTIFACTS_DIR}/git/tink_java_gcpkms
#  ${KOKORO_ARTIFACTS_DIR}/git/tink_tinkey
#
# If this is not the case, we are using this script locally for a manual on-off
# test (running it from the root of a local copy of the tink-examples
# repository), and so we are going to checkout tink from GitHub).
if [[ ( -z "${TINK_BASE_DIR:-}" && -z "${KOKORO_ROOT:-}") \
      || -n "${KOKORO_ROOT:-}" ]]; then
  TINK_BASE_DIR="$(pwd)/.."
  if [[ ! -d "${TINK_BASE_DIR}/tink_java" ]]; then
    git clone https://github.com/tink-crypto/tink-java.git \
      "${TINK_BASE_DIR}/tink_java"
  fi
  if [[ ! -d "${TINK_BASE_DIR}/tink_java_awskms" ]]; then
    git clone https://github.com/tink-crypto/tink-java-awskms.git \
      "${TINK_BASE_DIR}/tink_java_awskms"
  fi
  if [[ ! -d "${TINK_BASE_DIR}/tink_java_gcpkms" ]]; then
    git clone https://github.com/tink-crypto/tink-java-gcpkms.git \
      "${TINK_BASE_DIR}/tink_java_gcpkms"
  fi
fi

echo "Using Tink Java from ${TINK_BASE_DIR}/tink_java"
echo "Using Tink Java AWS KMS from ${TINK_BASE_DIR}/tink_java_awskms"
echo "Using Tink Java Google Cloud KMS from ${TINK_BASE_DIR}/tink_java_gcpkms"

# Sourcing required to update caller's environment.
source ./kokoro/testutils/install_python3.sh
./kokoro/testutils/copy_credentials.sh "java_src/testdata"
./kokoro/testutils/update_android_sdk.sh

cp "WORKSPACE" "WORKSPACE.bak"

./kokoro/testutils/replace_http_archive_with_local_repository.py \
  -f "WORKSPACE" \
  -t "${TINK_BASE_DIR}"

# Tests that require AWS/Google Cloud KMS credentials are only run in Kokoro.
TINK_TINKEY_MANUAL_TARGETS=()
if [[ -n "${KOKORO_ROOT:-}" ]]; then
  TINK_TINKEY_MANUAL_TARGETS+=(
    "//src/test/java/com/google/crypto/tink/tinkey:AddKeyCommandTest"
    "//src/test/java/com/google/crypto/tink/tinkey:CreatePublicKeysetCommandTest"
    "//src/test/java/com/google/crypto/tink/tinkey:CreateKeysetCommandTest"
    "//src/test/java/com/google/crypto/tink/tinkey:RotateKeysetCommandTest"
  )
fi
readonly TINK_TINKEY_MANUAL_TARGETS

./kokoro/testutils/run_bazel_tests.sh . "${TINK_TINKEY_MANUAL_TARGETS[@]}"

mv "WORKSPACE.bak" "WORKSPACE"
