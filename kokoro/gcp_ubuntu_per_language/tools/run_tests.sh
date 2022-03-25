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

cd ${KOKORO_ARTIFACTS_DIR}/git/tink

./kokoro/testutils/copy_credentials.sh
./kokoro/testutils/update_android_sdk.sh
# Sourcing required to update callers environment.
source ./kokoro/testutils/install_python3.sh
source ./kokoro/testutils/install_go.sh

echo "Using go binary from $(which go): $(go version)"

cd tools
use_bazel.sh $(cat .bazelversion)
time bazel build -- ...
time bazel test --test_output=errors -- ...

# Run manual tests which rely on key material injected into the Kokoro
# environement.
if [[ -n "${KOKORO_ROOT}" ]]; then
  declare -a MANUAL_TARGETS
  MANUAL_TARGETS=(
    "//testing/cc:gcp_kms_aead_test"
    "//testing/cross_language:aead_envelope_test"
  )
  readonly MANUAL_TARGETS
  time bazel test --test_output=errors -- "${MANUAL_TARGETS[@]}"
fi
