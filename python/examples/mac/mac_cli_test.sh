#!/bin/bash
# Copyright 2021 Google LLC
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
# Tests for MAC Python example.
#############################################################################

CLI="$1"
KEYSET_FILE="$2"

DATA_FILE="${TEST_TMPDIR}/example_data.txt"
MAC_FILE="${TEST_TMPDIR}/expected_mac.txt"

echo "This is some message to be verified." > "${DATA_FILE}"

#############################################################################

# A helper function for getting the return code of a command that may fail
# Temporarily disables error safety and stores return value in $TEST_STATUS
# Usage:
# % test_command somecommand some args
# % echo $TEST_STATUS
test_command() {
  set +e
  "$@"
  TEST_STATUS=$?
  set -e
}

print_test() {
  echo "+++ Starting test $1..."
}

#############################################################################

print_test "mac_computation_and_verification"

# Run computation.
${CLI} --mode compute --keyset_path "${KEYSET_FILE}" \
  --data_path "${DATA_FILE}" --mac_path "${MAC_FILE}"

# Run verification.
test_command ${CLI} --mode verify --keyset_path "${KEYSET_FILE}" \
  --data_path "${DATA_FILE}" --mac_path "${MAC_FILE}"

if (( TEST_STATUS == 0 )); then
  echo "+++ Success: MAC computation was successful."
else
  echo "--- Failure: MAC computation was unsuccessful"
  exit 1
fi


#############################################################################

print_test "mac_verification_fails_with_incorrect_mac"

# Run computation.
${CLI} --mode compute --keyset_path "${KEYSET_FILE}" \
  --data_path "${DATA_FILE}" --mac_path "${MAC_FILE}"

# Modify MAC.
echo "DEADBEEF" >> "${MAC_FILE}"

# Run verification.
test_command ${CLI} --mode verify --keyset_path "${KEYSET_FILE}" \
  --data_path "${DATA_FILE}" --mac_path "${MAC_FILE}"

if (( TEST_STATUS != 0 )); then
  echo "+++ Success: MAC verification failed for a modified mac."
else
  echo "--- Failure: MAC verification passed for a modified mac."
  exit 1
fi


#############################################################################

print_test "mac_verification_fails_with_modified_message"

# Run computation.
${CLI} --mode compute --keyset_path "${KEYSET_FILE}" \
  --data_path "${DATA_FILE}" --mac_path "${MAC_FILE}"

# Modify MAC.
echo "modified" >> "${DATA_FILE}"

# Run verification.
test_command ${CLI} --mode verify --keyset_path "${KEYSET_FILE}" \
  --data_path "${DATA_FILE}" --mac_path "${MAC_FILE}"

if (( TEST_STATUS != 0 )); then
  echo "+++ Success: MAC verification failed for a modified message."
else
  echo "--- Failure: MAC verification passed for a modified message."
  exit 1
fi


#############################################################################

print_test "bad_key_computation"

# Create a plaintext and bad keyset.
BAD_KEY_FILE="${TEST_TMPDIR}/bad_key.txt"
echo "not a key" > "${BAD_KEY_FILE}"

# Run computation.
test_command ${CLI} --mode compute --keyset_path "${BAD_KEY_FILE}" \
  --data_path "${DATA_FILE}" --mac_path "${MAC_FILE}"

if (( TEST_STATUS != 0 )); then
  echo "+++ Success: MAC computation failed with bad keyset."
else
  echo "--- Failure: MAC computation did not fail with bad keyset"
  exit 1
fi
