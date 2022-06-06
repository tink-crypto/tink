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
  cd "${KOKORO_ARTIFACTS_DIR}/git/tink_examples"
fi

# Note: When running on the Kokoro CI, we expect these folders to exist:
#
#  ${KOKORO_ARTIFACTS_DIR}/git/tink_java
#  ${KOKORO_ARTIFACTS_DIR}/git/tink_java_awskms
#  ${KOKORO_ARTIFACTS_DIR}/git/tink_java_gcpkms
#  ${KOKORO_ARTIFACTS_DIR}/git/tink_examples
#
# If this is not the case, we are using this script locally for a manual on-off
# test (running it from the root of a local copy of the tink-examples
# repository), and so we are going to checkout tink from GitHub).
if [[ (! -n "${TINK_BASE_DIR:-}" && ! -n "${KOKORO_ROOT:-}") \
      || -n "${KOKORO_ROOT:-}" ]]; then
  TINK_BASE_DIR="$(pwd)/.."
  if [[ ! -d "${TINK_BASE_DIR}/tink_java" ]]; then
    git clone https://github.com/tink-crypto/tink-java.git \
      "${TINK_BASE_DIR}/tink_java"
  fi
  if [[ ! -d "${TINK_BASE_DIR}/tink_java_gcpkms" ]]; then
    git clone https://github.com/tink-crypto/tink-java-gcpkms.git \
      "${TINK_BASE_DIR}/tink_java_gcpkms"
  fi
fi

echo "Using Tink Java from ${TINK_BASE_DIR}/tink_java"
echo "Using Tink Java Google Cloud KMS from ${TINK_BASE_DIR}/tink_java_gcpkms"

# Sourcing required to update caller's environment.
source ./kokoro/testutils/install_python3.sh
./kokoro/testutils/copy_credentials.sh "java_src/testdata"
./kokoro/testutils/update_android_sdk.sh

readonly WORKSPACE_FOLDER="java_src"

if [[ -n "${KOKORO_ROOT:-}" ]]; then
  use_bazel.sh "$(cat ${WORKSPACE_FOLDER}/.bazelversion)"
fi
cp "${WORKSPACE_FOLDER}/WORKSPACE" "${WORKSPACE_FOLDER}/WORKSPACE.bak"

./kokoro/testutils/replace_http_archive_with_local_reposotory.py \
  -f "${WORKSPACE_FOLDER}/WORKSPACE" \
  -t "${TINK_BASE_DIR}"

# Targets tagged as "manual" that require setting GCP credentials.
MANUAL_EXAMPLE_JAVA_TARGETS=()
if [[ -n "${KOKORO_ROOT:-}" ]]; then
  MANUAL_EXAMPLE_JAVA_TARGETS=(
    "//gcs:gcs_envelope_aead_example_test"
    "//encryptedkeyset:encrypted_keyset_example_test"
    "//envelopeaead:envelope_aead_example_test"
  )
fi
readonly MANUAL_EXAMPLE_JAVA_TARGETS

./kokoro/testutils/run_bazel_tests.sh \
  "${WORKSPACE_FOLDER}" \
  "${MANUAL_EXAMPLE_JAVA_TARGETS[@]}"

mv "${WORKSPACE_FOLDER}/WORKSPACE.bak" "${WORKSPACE_FOLDER}/WORKSPACE"
