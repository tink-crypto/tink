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

if [[ -n "${KOKORO_ROOT:-}" ]]; then
  cd "${KOKORO_ARTIFACTS_DIR}/git/tink"
  use_bazel.sh "$(cat go/.bazelversion)"
fi

./kokoro/testutils/copy_credentials.sh "go/testdata"
# Sourcing required to update callers environment.
source ./kokoro/testutils/install_go.sh

echo "Using go binary from $(which go): $(go version)"

./kokoro/testutils/check_go_generated_files_up_to_date.sh go/

MANUAL_TARGETS=()
# Run manual tests that rely on test data only available via Bazel.
if [[ -n "${KOKORO_ROOT:-}" ]]; then
  MANUAL_TARGETS+=(
    "//integration/gcpkms:gcpkms_test"
    "//integration/awskms:awskms_test"
  )
fi
readonly MANUAL_TARGETS

./kokoro/testutils/run_bazel_tests.sh go "${MANUAL_TARGETS[@]}"
