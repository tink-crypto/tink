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

#############################################################################
# Tests for Tink CC MAC.
#############################################################################

readonly CLI="$1"
readonly KEYSET_FILE="$2"
readonly DATA_FILE="${TEST_TMPDIR}/example_data.txt"
readonly TEST_NAME="TinkExamplesCcMacTest"

echo "This is some input data to be authenticated." > "${DATA_FILE}"

#######################################
# A helper function for getting the return code of a command that may fail.
# Temporarily disables error safety and stores return value in TEST_STATUS.
#
# Globals:
#   TEST_STATUS
# Arguments:
#   Command to execute.
#######################################
test_command() {
  set +e
  "$@"
  TEST_STATUS=$?
  set -e
}

#######################################
# Asserts that the outcome of the latest test command was the expected one.
#
# If not, it terminates the test execution.
#
# Globals:
#   TEST_STATUS
#   TEST_NAME
#   TEST_CASE
# Arguments:
#   expected_outcome: The expected outcome.
#######################################
_assert_test_command_outcome() {
  expected_outcome="$1"
  if (( TEST_STATUS != expected_outcome )); then
      echo "[   FAILED ] ${TEST_NAME}.${TEST_CASE}"
      exit 1
  fi
}

assert_command_succeeded() {
  _assert_test_command_outcome 0
}

assert_command_failed() {
  _assert_test_command_outcome 1
}

#######################################
# Starts a new test case; records the test case name to TEST_CASE.
#
# Globals:
#   TEST_NAME
#   TEST_CASE
# Arguments:
#   test_case: The name of the test case.
#######################################
start_test_case() {
  TEST_CASE="$1"
  echo "[ RUN      ] ${TEST_NAME}.${TEST_CASE}"
}

#######################################
# Ends a test case printing a success message.
#
# Globals:
#   TEST_NAME
#   TEST_CASE
#######################################
end_test_case() {
  echo "[       OK ] ${TEST_NAME}.${TEST_CASE}"
}

#############################################################################

start_test_case "compute"

# Run MAC computation.
test_command "${CLI}" \
  --mode compute \
  --keyset_filename "${KEYSET_FILE}" \
  --data_filename "${DATA_FILE}" \
  --tag_filename "${DATA_FILE}.tag"
assert_command_succeeded

end_test_case

#############################################################################

start_test_case "verify"

# Run MAC verification.
test_command "${CLI}" \
  --mode verify \
  --keyset_filename "${KEYSET_FILE}" \
  --data_filename "${DATA_FILE}" \
  --tag_filename "${DATA_FILE}.tag"
assert_command_succeeded

end_test_case

#############################################################################

start_test_case "verify_fails_with_modified_input_data"

# Run MAC computation.
test_command "${CLI}" \
  --mode compute \
  --keyset_filename "${KEYSET_FILE}" \
  --data_filename "${DATA_FILE}" \
  --tag_filename "${DATA_FILE}.tag"
assert_command_succeeded

# Copy input file.
cp "${DATA_FILE}" "${DATA_FILE}.copy"

# Verify with unmodified input.
test_command "${CLI}" \
  --mode verify \
  --keyset_filename "${KEYSET_FILE}" \
  --data_filename "${DATA_FILE}.copy" \
  --tag_filename "${DATA_FILE}.tag"
assert_command_succeeded

# Modify copy of input file.
echo "modified" >> "${DATA_FILE}.copy"

# Verify with modified input.
test_command "${CLI}" \
  --mode verify \
  --keyset_filename "${KEYSET_FILE}" \
  --data_filename "${DATA_FILE}.copy" \
  --tag_filename "${DATA_FILE}.tag"
assert_command_failed

end_test_case

#############################################################################

start_test_case "verify_fails_with_modified_tag"

# Run MAC computation.
test_command "${CLI}" \
  --mode compute \
  --keyset_filename "${KEYSET_FILE}" \
  --data_filename "${DATA_FILE}" \
  --tag_filename "${DATA_FILE}.tag"
assert_command_succeeded

# Copy tag.
cp "${DATA_FILE}.tag" "${DATA_FILE}.tag.copy"

# Verify with unmodified tag.
test_command "${CLI}" \
  --mode verify \
  --keyset_filename "${KEYSET_FILE}" \
  --data_filename "${DATA_FILE}" \
  --tag_filename "${DATA_FILE}.tag.copy"
assert_command_succeeded

# Modify copy of tag.
echo "modified" >> "${DATA_FILE}.tag.copy"

# Verify with modified tag.
test_command "${CLI}" \
  --mode verify \
  --keyset_filename "${KEYSET_FILE}" \
  --data_filename "${DATA_FILE}" \
  --tag_filename "${DATA_FILE}.tag.copy"
assert_command_failed

end_test_case
