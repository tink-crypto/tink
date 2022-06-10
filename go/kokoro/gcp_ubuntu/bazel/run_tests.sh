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

if [[ -n "${KOKORO_ROOT:-}" ]]; then
  cd "${KOKORO_ARTIFACTS_DIR}/git/tink_go"
fi

# Sourcing required to update callers environment.
source ./kokoro/testutils/install_go.sh

echo "Using go binary from $(which go): $(go version)"

if [[ -n "${KOKORO_ROOT:-}" ]]; then
  use_bazel.sh "$(cat go/.bazelversion)"
fi

# Check that build files are up-to-date.
TEMP_DIR_CURRENT="$(mktemp -dt current_tink_go_build_files.XXXXXX)"
REPO_FILES=(
  ./go.mod
  ./go.sum
  ./deps.bzl
)

# Copy all current generated build files into TEMP_DIR_CURRENT
readarray -t CURRENT_GENERATED_FILES < <(find . -name BUILD.bazel)
CURRENT_GENERATED_FILES+=( "${REPO_FILES[@]}" )

readonly CURRENT_GENERATED_FILES
for generated_file_path in "${CURRENT_GENERATED_FILES[@]}"; do
  mkdir -p "$(dirname "${TEMP_DIR_CURRENT}/${generated_file_path}")"
  cp "${generated_file_path}" "${TEMP_DIR_CURRENT}/${generated_file_path}"
done

# Update build files
go mod tidy
# Update deps.bzl
bazel run //:gazelle-update-repos
# Update all BUILD.bazel files
bazel run //:gazelle

# Compare current with new build files
readarray -t NEW_GENERATED_FILES < <(find . -name BUILD.bazel)
NEW_GENERATED_FILES+=( "${REPO_FILES[@]}" )
readonly NEW_GENERATED_FILES
for generated_file_path in "${NEW_GENERATED_FILES[@]}"; do
  if ! cmp -s "${generated_file_path}" "${TEMP_DIR_CURRENT}/${generated_file_path}"; then
    echo "FAIL: ${generated_file_path} needs to be updated. Please follow the instructions on go/tink-workflows#update-go-build."
    exit 1
  fi
done

./kokoro/testutils/run_bazel_tests.sh go
