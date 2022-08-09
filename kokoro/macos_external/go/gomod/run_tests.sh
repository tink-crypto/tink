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

REPO_DIR="${KOKORO_ARTIFACTS_DIR}/git/tink"

cd "${REPO_DIR}"
./kokoro/testutils/copy_credentials.sh "go/testdata" "all"
# Sourcing required to update callers environment.
source ./kokoro/testutils/install_go.sh

echo "Using go binary from $(which go): $(go version)"

readonly TINK_VERSION="$(cat ${REPO_DIR}/go/tink_version.bzl \
                        | grep ^TINK \
                        | cut -f 2 -d \")"

# Create a temporary directory for performing module tests.
TMP_DIR="$(mktemp -dt go-module-test.XXXXXX)"
GO_MOD_DIR="${TMP_DIR}/go-mod-test"

REPO_URL_PREFIX="github.com/google/tink"

#######################################
# Test an individual Go module within the Tink repository.
# Globals:
#   REPO_DIR
#   TINK_VERISON
#   GO_MOD_DIR
#   REPO_URL_PREFIX
# Arguments:
#   The name of the Go module, relative to the repository root.
# Outputs:
#   Prints progress to STDOUT.
#######################################
function test_go_mod() {
  local mod_name="$1"
  local full_mod_name="${REPO_URL_PREFIX}/${mod_name}"

  echo "### Testing ${full_mod_name}..."
  (
    echo "Using go binary from $(which go): $(go version)"
    set -x
    cd "${REPO_DIR}/${mod_name}"
    go build -v ./...
    go test -v ./...
  )

  mkdir "${GO_MOD_DIR}"
  (
    cd "${GO_MOD_DIR}"

    echo "Using go binary from $(which go): $(go version)"

    # Display commands being run for the remainder of this subshell.
    set -x

    # Initialize a test Go module.
    go mod init tink-go-mod-test
    overlay_module "${mod_name}" "${full_mod_name}"
    overlay_internal_deps "${mod_name}"

    # Print the prepared go.mod.
    cat go.mod

    # Get the module at the latest commit and print graph output depicting
    # direct dependencies.
    go get -v "${full_mod_name}@master"

    # Pint contextual information concerning dependencies.
    go mod graph | grep google/tink
    go list -m all | grep google/tink
  )

  # Leave a clean environment for subsequent tests.
  go clean -modcache
  rm -rf "${GO_MOD_DIR}"
}

#######################################
# Add a require statement for a Tink module and a replace statement to point it
# to the local copy.
# Globals:
#   REPO_DIR
#   TINK_VERISON
# Arguments:
#   The name of the Go module, relative to the repository root.
#   The full name of the Go module, as specified in import statements.
#######################################
function overlay_module() {
  local mod_name="$1"
  local full_mod_name="$2"

  go mod edit "-require=${full_mod_name}@v${TINK_VERSION}"
  go mod edit "-replace=${full_mod_name}=${REPO_DIR}/${mod_name}"
}

#######################################
# Search the go.mod being tested for internal dependencies and overlay them with
# the local copies.
# Globals:
#   REPO_DIR
#   REPO_URL_PREFIX
# Arguments:
#   The name of the Go module being tested, relative to the repository root.
#######################################
function overlay_internal_deps() {
  local mod_name="$1"

  declare -a internal_deps
  while read internal_dep; do
    internal_deps+=("${internal_dep}")
  done < <(grep "${REPO_URL_PREFIX}" "${REPO_DIR}/${mod_name}/go.mod" \
      | grep -v ^module \
      | awk '{print $1}')

  # If internal_deps are found...
  if [[ ! -z "${internal_deps+x}" ]]; then
    for full_dep_name in "${internal_deps[@]}"; do
      local dep_name="$(echo "${full_dep_name}" | sed "s#${REPO_URL_PREFIX}/##")"
      overlay_module "${dep_name}" "${full_dep_name}"
    done
  fi
}

function main() {
  # Extract all go.mod instances from the repository.
  declare -a go_mod_dirs
  while read go_mod_dir; do
    go_mod_dirs+=("${go_mod_dir}")
  done < <(find "${REPO_DIR}" -name "go.mod" \
    | sed "s#^${REPO_DIR}/##" \
    | xargs -n 1 dirname)

  echo "### Go modules found:"
  for go_mod_dir in "${go_mod_dirs[@]}"; do
    echo "${go_mod_dir}"
  done

  for go_mod_dir in "${go_mod_dirs[@]}"; do
    test_go_mod "${go_mod_dir}"
  done
}

main "$@"
