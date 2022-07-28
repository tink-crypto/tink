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

# This script runs tests on a given Go module.
#
# Usage:
#   ./kokoro/testutils/run_gomod_tests.sh \
#     <Full module URL> \
#     <Local path of the Go module> \
#     <Module version> \
#     <Branch at HEAD for the Go module on GitHub>

set -eo pipefail

FULL_GITHUB_MODULE_NAME=
GO_MODULE_LOCAL_PATH=
GO_MODULE_VERSION=
GO_MODULE_GITHUB_HEAD_BRANCH=

usage() {
  echo "Usage: $0 <full module URL> <go module's local path> \\"
  echo "         <module version> <branch at HEAD>"
  exit 1
}

#######################################
# Process command line arguments.
#
# Globals:
#   FULL_GITHUB_MODULE_NAME
#   GO_MODULE_LOCAL_PATH
#   GO_MODULE_VERSION
#   GO_MODULE_GITHUB_HEAD_BRANCH
#######################################
process_args() {
  FULL_GITHUB_MODULE_NAME="$1"
  readonly FULL_GITHUB_MODULE_NAME
  GO_MODULE_LOCAL_PATH="$2"
  readonly GO_MODULE_LOCAL_PATH
  GO_MODULE_VERSION="$3"
  readonly GO_MODULE_VERSION
  GO_MODULE_GITHUB_HEAD_BRANCH="$4"
  readonly GO_MODULE_GITHUB_HEAD_BRANCH

  if [[ -z "${FULL_GITHUB_MODULE_NAME}" ]]; then
    usage
  fi
  if [[ -z "${GO_MODULE_LOCAL_PATH}" ]]; then
    usage
  fi
  if [[ -z "${GO_MODULE_VERSION}" ]]; then
    usage
  fi
  if [[ -z "${GO_MODULE_GITHUB_HEAD_BRANCH}" ]]; then
    usage
  fi
}

#######################################
# Add a require statement for a module and a replace statement to point it
# to the local copy.
# Arguments:
#   full_github_module_name: The full module name.
#   module_local_path: The root directory of the local Go module.
#   tink_version: Tink version.
#######################################
function overlay_module() {
  local full_github_module_name="$1"
  local module_local_path="$2"
  local tink_version="$3"

  go mod edit "-require=${full_github_module_name}@v${tink_version}"
  go mod edit "-replace=${full_github_module_name}=${module_local_path}"
}

#######################################
# Search the go.mod being tested for internal dependencies and overlay them with
# the local copies.
#
# Globals:
#   FULL_GITHUB_MODULE_NAME
#   GO_MODULE_LOCAL_PATH
#   GO_MODULE_VERSION
#######################################
overlay_internal_deps() {
  declare -a internal_deps
  while read internal_dep; do
    internal_deps+=("${internal_dep}")
  done < <(grep "${FULL_GITHUB_MODULE_NAME}" "${GO_MODULE_LOCAL_PATH}/go.mod" \
        | grep -v ^module \
        | awk '{print $1}')

  # If internal_deps are found...
  if [[ ! -z "${internal_deps+x}" ]]; then
    for full_dep_name in "${internal_deps[@]}"; do
      local dep_name="$(echo "${full_dep_name}" \
        | sed "s#${FULL_GITHUB_MODULE_NAME}/##")"
      overlay_module \
        "${full_dep_name}" \
        "${dep_name}" \
        "${GO_MODULE_VERSION}"
    done
  fi
}

#######################################
# Builds and tests a given local module.
#
# Globals:
#   GO_MODULE_LOCAL_PATH
# Outputs:
#   Prints progress to STDOUT.
#######################################
build_and_test_local_go_mod() {
  echo "### Testing local Go module at ${GO_MODULE_LOCAL_PATH}"
  (
    set -x
    cd "${GO_MODULE_LOCAL_PATH}"
    go build -v ./...
    go test -v ./...
  )
}

#######################################
# Builds and tests a given local module.
#
# Globals:
#   FULL_GITHUB_MODULE_NAME
#   GO_MODULE_LOCAL_PATH
#   GO_MODULE_VERSION
#   GO_MODULE_GITHUB_HEAD_BRANCH
# Outputs:
#   Prints progress to STDOUT.
#######################################
test_go_module_depending_on_local_one() {
  # Create a temporary directory for performing module tests.
  local -r test_tmp_dir="$(mktemp -dt tink-gomod-test.XXXXXX)"
  local -r go_module_tmp_directory="${test_tmp_dir}/go-mod-test"
  mkdir "${go_module_tmp_directory}"
  (
    cd "${go_module_tmp_directory}"
    echo "Using go binary from $(which go): $(go version)"

    set -x
    # Initialize a test Go module.
    go mod init tink-go-mod-test
    overlay_module \
      "${FULL_GITHUB_MODULE_NAME}" \
      "${GO_MODULE_LOCAL_PATH}" \
      "${GO_MODULE_VERSION}"
    overlay_internal_deps

    # Print the prepared go.mod.
    cat go.mod

    # Get the module at the latest commit and print graph output depicting
    # direct dependencies.
    go get -v "${FULL_GITHUB_MODULE_NAME}@${GO_MODULE_GITHUB_HEAD_BRANCH}"

    # Pint contextual information concerning dependencies.
    go mod graph | grep tink
    go list -m all | grep tink
  )

  # Leave a clean environment for subsequent tests.
  go clean -modcache
  rm -rf "${test_tmp_dir}"
}

main() {
  process_args "$@"
  build_and_test_local_go_mod
  # Skip this test for modules that are not on github.com/google/tink.
  if [[ "${FULL_GITHUB_MODULE_NAME}" =~ github.com/google/tink[a-z./]+ ]]; then
    test_go_module_depending_on_local_one
  fi
}

main "$@"
