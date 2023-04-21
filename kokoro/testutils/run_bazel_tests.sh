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

# Note: -E extends the trap to shell functions, command substitutions, and
# commands executed in a subshell environment.
set -eEo pipefail
# Print some debug output on error before exiting.
trap print_debug_output ERR

usage() {
  echo "Usage: $0 [-mh] [-b <build parameter> ...] [-t <test parameter> ...] \\"
  echo "         <workspace directory> [<manual target> <manual target> ...]"
  echo "  -m: Runs only the manual targets. If set, manual targets must be"
  echo "      provided."
  echo "  -b: Comma separated list of flags to pass to `bazel build`."
  echo "  -t: Comma separated list of flags to pass to `bazel test`."
  echo "  -h: Help. Print this usage information."
  exit 1
}

readonly PLATFORM="$(uname | tr '[:upper:]' '[:lower:]')"
MANUAL_ONLY="false"
WORKSPACE_DIR=
MANUAL_TARGETS=
BAZEL_CMD="bazel"
BUILD_FLAGS=()
TEST_FLAGS=()

#######################################
# Process command line arguments.
#
# Globals:
#   WORKSPACE_DIR
#   MANUAL_TARGETS
#######################################
process_args() {
  # Parse options.
  while getopts "mhb:t:" opt; do
    case "${opt}" in
      m) MANUAL_ONLY="true" ;;
      b) BUILD_FLAGS=($(echo "${OPTARG}" | tr ',' '\n')) ;;
      t) TEST_FLAGS=($(echo "${OPTARG}" | tr ',' '\n')) ;;
      *) usage ;;
    esac
  done
  shift $((OPTIND - 1))

  WORKSPACE_DIR="$1"
  readonly WORKSPACE_DIR

  if [[ -z "${WORKSPACE_DIR}" ]]; then
    usage
  fi

  shift 1
  MANUAL_TARGETS=("$@")
  readonly MANUAL_TARGETS

  if [[ "${MANUAL_ONLY}" == "true" ]] && (( ${#MANUAL_TARGETS[@]} == 0 )); then
    usage
  fi

  # Use Bazelisk (https://github.com/bazelbuild/bazelisk) if available.
  if command -v "bazelisk" &> /dev/null; then
    BAZEL_CMD="bazelisk"
  fi
  readonly BAZEL_CMD
  echo "Using: $(which ${BAZEL_CMD})"
}

#######################################
# Print some debugging output.
#######################################
print_debug_output() {
  ls -l
  df -h
}

main() {
  process_args "$@"

  TEST_FLAGS+=(
    --strategy=TestRunner=standalone
    --test_output=all
  )

  local -r workspace_dir="$(cd ${WORKSPACE_DIR} && pwd)"

  if [[ "${PLATFORM}" == 'darwin' ]]; then
    TEST_FLAGS+=( --jvmopt="-Djava.net.preferIPv6Addresses=true" )
    if [[ "${workspace_dir}" =~ javascript ]]; then
      BUILD_FLAGS+=( --experimental_inprocess_symlink_creation )
      TEST_FLAGS+=( --experimental_inprocess_symlink_creation )
    fi
  fi
  readonly BUILD_FLAGS
  readonly TEST_FLAGS
  (
    set -x
    cd "${workspace_dir}"
    if [[ "${MANUAL_ONLY}" == "false" ]]; then
      time "${BAZEL_CMD}" build "${BUILD_FLAGS[@]}" -- ...
      # Exit code 4 means targets build correctly but no tests were found. See
      # https://bazel.build/docs/scripts#exit-codes.
      bazel_test_return=0
      time "${BAZEL_CMD}" test "${TEST_FLAGS[@]}" -- ... || bazel_test_return="$?"
      if (( $bazel_test_return != 0 && $bazel_test_return != 4 )); then
        return "${bazel_test_return}"
      fi
    fi
    # Run specific manual targets.
    if (( ${#MANUAL_TARGETS[@]} > 0 )); then
      time "${BAZEL_CMD}" build "${BUILD_FLAGS[@]}" -- "${MANUAL_TARGETS[@]}"
      time "${BAZEL_CMD}" test "${TEST_FLAGS[@]}"  -- "${MANUAL_TARGETS[@]}"
    fi
  )
}

main "$@"
