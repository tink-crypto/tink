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

set -euo pipefail

TINK_GO_PROJECT_PATH="$(pwd)"
if [[ -n "${KOKORO_ROOT:-}" ]]; then
  TINK_GO_PROJECT_PATH="${KOKORO_ARTIFACTS_DIR}/git/tink_go"
  cd "${TINK_GO_PROJECT_PATH}"
fi
readonly TINK_GO_PROJECT_PATH

./kokoro/testutils/update_certs.sh
# Sourcing required to update callers environment.
source ./kokoro/testutils/install_go.sh

echo "Using go binary from $(which go): $(go version)"

readonly TINK_GO_MODULE_URL="github.com/tink-crypto/tink-go"
readonly TINK_VERSION="$(cat ${TINK_GO_PROJECT_PATH}/tink_version.bzl \
                        | grep ^TINK \
                        | cut -f 2 -d \")"
# Create a temporary directory for performing module tests.
readonly TMP_DIR="$(mktemp -dt go-module-test.XXXXXX)"

./kokoro/testutils/run_go_mod_tests.sh \
  "${TINK_GO_MODULE_URL}" \
  "${TINK_GO_PROJECT_PATH}" \
  "${TMP_DIR}" \
  "${TINK_VERSION}"
