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

REPO_DIR="$(pwd)"
if [[ -n "${KOKORO_ROOT:-}" ]]; then
  REPO_DIR="${KOKORO_ARTIFACTS_DIR}/git/tink"
  cd "${REPO_DIR}"
fi
readonly REPO_DIR

./kokoro/testutils/copy_credentials.sh "go/testdata" "all"
./kokoro/testutils/update_certs.sh
# Sourcing required to update callers environment.
source ./kokoro/testutils/install_go.sh

echo "Using go binary from $(which go): $(go version)"

readonly TINK_VERSION="$(cat ${REPO_DIR}/go/tink_version.bzl \
                        | grep ^TINK \
                        | cut -f 2 -d \")"

# Create a temporary directory for performing module tests.
readonly TMP_DIR="$(mktemp -dt go-module-test.XXXXXX)"
readonly REPO_URL_PREFIX="github.com/google/tink"

# Extract all go.mod instances from the repository.
declare -a GO_MODULE_DIRECTORIES
while read go_module_directory; do
  GO_MODULE_DIRECTORIES+=("${go_module_directory}")
done < <(find "${REPO_DIR}" -name "go.mod" \
  | sed "s#^${REPO_DIR}/##" \
  | xargs -n 1 dirname)

echo "### Go modules found:"

for go_module_directory in "${GO_MODULE_DIRECTORIES[@]}"; do
  echo "${go_module_directory}"
done

for go_module_directory in "${GO_MODULE_DIRECTORIES[@]}"; do
  ./kokoro/testutils/run_go_mod_tests.sh \
    "${REPO_URL_PREFIX}/${go_module_directory}" \
    "${REPO_DIR}/${go_module_directory}" \
    "${TINK_VERSION}" \
    "master"
done
