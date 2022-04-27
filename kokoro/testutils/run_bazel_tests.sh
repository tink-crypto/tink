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

# This script runs all the Bazel tests within a given workspace directory.
#
# Users must spcify the WORKSPACE directory. Optionally, the user can specify
# a set of additional manual targets to run.
#
# Usage:
#   ./kokoro/testutils/run_bazel_tests.sh \
#     <workspace directory> \
#     [<manual target> <manual target> ...]

#######################################
# Print some debugging output then fail.
# Globals:
#   None
# Arguments:
#   None
#######################################
fail_with_debug_output() {
  ls -l
  df -h /
  exit 1
}

#######################################
# Runs the tests contained in the given Bazel workspace.
# Globals:
#   None
# Arguments:
#   workspace_dir: The workspace directory path.
#   manual_targets: (optional) Additional manual test targets.
#######################################
run_bazel_tests() {
  local workspace_dir="$1"
  shift 1
  local manual_targets=("$@")

  readonly PLATFORM="$(uname | tr '[:upper:]' '[:lower:]')"

  local -a TEST_FLAGS=( --strategy=TestRunner=standalone --test_output=all )
  if [[ "${PLATFORM}" == 'darwin' ]]; then
    TEST_FLAGS+=( --jvmopt="-Djava.net.preferIPv6Addresses=true" )
  fi
  readonly TEST_FLAGS
  (
    cd "${workspace_dir}"
    time bazel build -- ... || fail_with_debug_output
    time bazel test "${TEST_FLAGS[@]}" -- ... || fail_with_debug_output
    # Run specific manual targets.
    if (( ${#manual_targets[@]} > 0 )); then
      time bazel test "${TEST_FLAGS[@]}"  -- "${manual_targets[@]}" \
        || fail_with_debug_output
    fi
  )
}

run_bazel_tests "$@"
