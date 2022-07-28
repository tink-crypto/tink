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
#     <Path of a temporary directory from where running the test> \
#     <Tink version>

#######################################
# Add a require statement for a Tink module and a replace statement to point it
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
# Arguments:
#   full_github_module_name: The full module name.
#   module_local_path: The root directory of the local Go module.
#   tink_version: Tink version.
#######################################
function overlay_internal_deps() {
  local full_github_module_name="$1"
  local module_local_path="$2"
  local tink_version="$3"

  declare -a internal_deps
  while read internal_dep; do
    internal_deps+=("${internal_dep}")
  done < <(grep "${full_github_module_name}" "${module_local_path}/go.mod" \
        | grep -v ^module \
        | awk '{print $1}')

  # If internal_deps are found...
  if [[ ! -z "${internal_deps+x}" ]]; then
    for full_dep_name in "${internal_deps[@]}"; do
      local dep_name="$(echo "${full_dep_name}" \
        | sed "s#${full_github_module_name}/##")"
      overlay_module \
        "${full_dep_name}" \
        "${dep_name}" \
        "${tink_version}"
    done
  fi
}

#######################################
# Test an individual Go module within the Tink repository.
#
# Arguments:
#   full_github_module_name: The full module name.
#   module_local_path: The root directory of the local Go module.
#   test_tmp_directory: A temporary directory to use for testing.
#   tink_version: Tink version.
# Outputs:
#   Prints progress to STDOUT.
#######################################
function test_go_mod() {
  local full_github_module_name="$1"
  local module_local_path="$2"
  local test_tmp_directory="$3"
  local tink_version="$4"

  echo "### Testing ${full_github_module_name}..."
  (
    set -x
    cd "${module_local_path}"
    go build -v ./...
    go test -v ./...
  )

  local go_module_tmp_directory="${test_tmp_directory}/go-mod-test"
  mkdir "${go_module_tmp_directory}"
  (
    cd "${go_module_tmp_directory}"

    echo "Using go binary from $(which go): $(go version)"

    # Display commands being run for the remainder of this subshell.
    set -x

    # Initialize a test Go module.
    go mod init tink-go-mod-test
    overlay_module \
      "${full_github_module_name}" \
      "${module_local_path}" \
      "${tink_version}"
    overlay_internal_deps \
      "${full_github_module_name}" \
      "${module_local_path}" \
      "${tink_version}"

    # Print the prepared go.mod.
    cat go.mod

    # Get the module at the latest commit and print graph output depicting
    # direct dependencies.
    go get -v "${full_github_module_name}@master"

    # Pint contextual information concerning dependencies.
    go mod graph | grep tink
    go list -m all | grep tink
  )

  # Leave a clean environment for subsequent tests.
  go clean -modcache
  rm -rf "${go_module_tmp_directory}"
}

test_go_mod "$@"
