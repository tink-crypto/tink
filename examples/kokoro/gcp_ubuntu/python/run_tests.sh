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

# Note: When running on the Kokoro CI, we expect these two folders to exist:
#
#  ${KOKORO_ARTIFACTS_DIR}/git/tink
#  ${KOKORO_ARTIFACTS_DIR}/git/tink_examples
#
# If this is not the case, we are using this script locally for a manual on-off
# test (running it from the root of a local copy of the tink-examples
# repository), and so we are going to checkout tink from GitHub).
if [[ (! -n "${TINK_BASE_DIR:-}" && ! -n "${KOKORO_ROOT:-}") \
      || -n "${KOKORO_ROOT:-}" ]]; then
  TINK_BASE_DIR="$(pwd)/../tink"
  if [[ ! -d "${TINK_BASE_DIR}" ]]; then
    git clone https://github.com/google/tink.git "${TINK_BASE_DIR}"
  fi
fi

# Sourcing required to update callers environment.
source ./kokoro/testutils/install_python3.sh
./kokoro/testutils/copy_credentials.sh "python/testdata"

readonly WORKSPACE_FOLDER="python"

# Targets tagged as "manual" that require setting GCP credentials.
MANUAL_EXAMPLE_PYTHON_TARGETS=()
if [[ -n "${KOKORO_ROOT:-}" ]]; then
  MANUAL_EXAMPLE_PYTHON_TARGETS=(
    "//gcs:gcs_envelope_aead_test_package"
    "//gcs:gcs_envelope_aead_test"
    "//envelope_aead:envelope_test_package"
    "//envelope_aead:envelope_test"
    "//encrypted_keyset:encrypted_keyset_test_package"
    "//encrypted_keyset:encrypted_keyset_test"
  )
fi
readonly MANUAL_EXAMPLE_PYTHON_TARGETS

if [[ -n "${KOKORO_ROOT:-}" ]]; then
  use_bazel.sh "$(cat ${WORKSPACE_FOLDER}/.bazelversion)"
fi
cp "${WORKSPACE_FOLDER}/WORKSPACE" "${WORKSPACE_FOLDER}/WORKSPACE.bak"
./kokoro/testutils/replace_http_archive_with_local_reposotory.py \
  -f "${WORKSPACE_FOLDER}/WORKSPACE" \
  -t "${TINK_BASE_DIR}"
./kokoro/testutils/run_bazel_tests.sh \
  "${WORKSPACE_FOLDER}" \
  "${MANUAL_EXAMPLE_PYTHON_TARGETS[@]}"
mv "${WORKSPACE_FOLDER}/WORKSPACE.bak" "${WORKSPACE_FOLDER}/WORKSPACE"
