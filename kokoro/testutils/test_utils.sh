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

# Set of utilities to run unit tests for bash scripts.
#
# Example usage:
# From your test script:
#   source some/path/to/test_utils.sh
#
#   # Test functions must be defined as follows:
#   test_<Test Name>_<Test Case Name>() {
#     # Do some ground work.
#     # Run the test script.
#     ./path/to/script_to_test <input1> <input2> ...
#     ASSERT_CMD_SUCCEEDED
#     ASSERT_FILE_EQUALS <file1> <file2>
#   }
#
#   # Finds all the functions starting with `test_`, extracts test name and
#   # test case, and run them.
#   run_all_tests "$@"
#

# This is either set by Bazel or generated.
: "${TEST_TMPDIR:="$(mktemp -td test.XXXXX)"}"
readonly TEST_TMPDIR

# Temporary directory for the testcase to use.
TEST_CASE_TMPDIR=

# Current test name.
_CURRENT_TEST_SCOPE=

# Current test case.
_CURRENT_TEST_CASE=

# True if at least one of the test cases terminated with an error.
_HAS_ERROR="false"

_print_testcase_failed_and_exit() {
  echo "[   FAILED ] ${_CURRENT_TEST_SCOPE}.${_CURRENT_TEST_CASE}"
  exit 1
}

#######################################
# Starts a new test case.
#
# Globals:
#   _CURRENT_TEST_SCOPE
#   _CURRENT_TEST_CASE
#######################################
_start_test_case() {
  echo "[ RUN      ] ${_CURRENT_TEST_SCOPE}.${_CURRENT_TEST_CASE}"
  # Create a tmp dir for the test case.
  TEST_CASE_TMPDIR="${TEST_TMPDIR}/${_CURRENT_TEST_SCOPE}/${_CURRENT_TEST_CASE}"
  mkdir -p "${TEST_CASE_TMPDIR}"
}

#######################################
# Ends a test case printing a success message.
#
# Globals:
#   _CURRENT_TEST_SCOPE
#   _CURRENT_TEST_CASE
#######################################
_end_test_case_with_success() {
  test_case="$1"
  echo "[       OK ] ${_CURRENT_TEST_SCOPE}.${_CURRENT_TEST_CASE}"
}

#######################################
# Returns the list of tests defined in the test script.
#
# A test case is a function of the form:
#     test_<Test Name>_<Test Case>
#
# This function returns all the functions starting with `test_`.
#
# Globals:
#   None
# Arguments:
#   None
#######################################
_get_all_tests() {
  declare -F |
    while read line; do
      case "${line}" in "declare -f test_"*)
          echo "${line#declare -f }"
        ;;
      esac
    done
}

#######################################
# Runs a given test function.
#
# A test case is a function of the form:
#     test_<Test Name>_<Test Case>
#
# This script extracts test name and test case from the name.
#
# Globals:
#   _CURRENT_TEST_SCOPE
# Arguments:
#   None
#######################################
_do_run_test() {
  test_function="$1"
  IFS=_ read _CURRENT_TEST_SCOPE _CURRENT_TEST_CASE <<< "${test_function#test_}"
  _start_test_case
  (
    # Make sure we exit only when assertions fail.
    set +e
    "${test_function}"
  )
  local -r result=$?
  if (( $result == 0 )); then
    _end_test_case_with_success
  else
    _HAS_ERROR="true"
  fi
}

#######################################
# Runs all the test cases defined in the test script file.
# Globals:
#   None
# Arguments:
#   None
#
#######################################
run_all_tests() {
  for test in $(_get_all_tests); do
    _do_run_test "${test}"
  done
  # Make sure we return an error code for the failing test
  if [[ "${_HAS_ERROR}" == "true" ]]; then
    exit 1
  fi
}

ASSERT_CMD_SUCCEEDED() {
  if (( $? != 0 )); then
      _print_testcase_failed_and_exit
  fi
}

ASSERT_CMD_FAILED() {
  if (( $? == 0 )); then
      _print_testcase_failed_and_exit
  fi
}

ASSERT_FILE_EQUALS() {
  input_file="$1"
  expected_file="$2"
  if ! diff "${input_file}" "${expected_file}"; then
    _print_testcase_failed_and_exit
  fi
}
