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
# Tests for Tink C++ hybrid encryption example.
#############################################################################

readonly CLI="$1"
readonly PRIVATE_KEYSET_FILE="$2"
readonly PUBLIC_KEYSET_FILE="$3"
readonly DATA_FILE="${TEST_TMPDIR}/example_data.txt"
readonly TEST_NAME="TinkExamplesCcHybridTest"

echo "This is some message to be encrypted." > "${DATA_FILE}"

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

start_test_case "encrypt"

# Run encryption.
test_command "${CLI}" \
  --mode encrypt \
  --keyset_filename "${PUBLIC_KEYSET_FILE}" \
  --input_filename "${DATA_FILE}" \
  --output_filename "${DATA_FILE}.encrypted"
assert_command_succeeded

end_test_case

#############################################################################

start_test_case "decrypt"

# Run decryption.
test_command "${CLI}" \
  --mode decrypt \
  --keyset_filename "${PRIVATE_KEYSET_FILE}" \
  --input_filename "${DATA_FILE}.encrypted" \
  --output_filename "${DATA_FILE}.decrypted"
assert_command_succeeded

test_command cmp -s "${DATA_FILE}" "${DATA_FILE}.decrypted"
assert_command_succeeded

end_test_case

#############################################################################

start_test_case "encrypt_decrypt_fails_with_modified_ciphertext"

# Run encryption
test_command "${CLI}" \
  --mode encrypt \
  --keyset_filename "${PUBLIC_KEYSET_FILE}" \
  --input_filename "${DATA_FILE}" \
  --output_filename "${DATA_FILE}.encrypted"
assert_command_succeeded

# Modify ciphertext.
echo "modified" >> "${DATA_FILE}.encrypted"

# Run decryption.
test_command "${CLI}" \
  --mode decrypt \
  --keyset_filename "${PRIVATE_KEYSET_FILE}" \
  --input_filename "${DATA_FILE}.encrypted" \
  --output_filename "${DATA_FILE}.decrypted"
assert_command_failed

end_test_case

#############################################################################

start_test_case "encrypt_decrypt_succeeds_with_context_info"

# Run encryption.
CONTEXT_INFO="header information"
test_command "${CLI}" \
  --mode encrypt \
  --keyset_filename "${PUBLIC_KEYSET_FILE}" \
  --input_filename "${DATA_FILE}" \
  --output_filename "${DATA_FILE}.encrypted" \
  --context_info "${CONTEXT_INFO}"
assert_command_succeeded

# Run decryption.
test_command "${CLI}" \
  --mode decrypt \
  --keyset_filename "${PRIVATE_KEYSET_FILE}" \
  --input_filename "${DATA_FILE}.encrypted" \
  --output_filename "${DATA_FILE}.decrypted" \
  --context_info "${CONTEXT_INFO}"
assert_command_succeeded

cmp --silent "${DATA_FILE}" "${DATA_FILE}.decrypted"
assert_command_succeeded

end_test_case

#############################################################################

start_test_case "encrypt_decrypt_fails_with_modified_context_info"

# Run encryption.
CONTEXT_INFO="header information"
test_command "${CLI}" \
  --mode encrypt \
  --keyset_filename "${PUBLIC_KEYSET_FILE}" \
  --input_filename "${DATA_FILE}" \
  --output_filename "${DATA_FILE}.encrypted" \
  --context_info "${CONTEXT_INFO}"
assert_command_succeeded

# Run decryption.
MODIFIED_CONTEXT_INFO="modified header information"
test_command "${CLI}" \
  --mode decrypt \
  --keyset_filename "${PRIVATE_KEYSET_FILE}" \
  --input_filename "${DATA_FILE}.encrypted" \
  --output_filename "${DATA_FILE}.decrypted" \
  --context_info "${MODIFIED_CONTEXT_INFO}"
assert_command_failed

end_test_case
