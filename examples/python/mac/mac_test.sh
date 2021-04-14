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
##### Tests for MAC Python example.

MAC_CLI="$1"
KEYSET_FILE="$2"

DATA_FILE="$TEST_TMPDIR/example_data.txt"
MAC_FILE="$TEST_TMPDIR/expected_mac.txt"

echo "This is some message to be verified." > $DATA_FILE

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


#############################################################################
#### Test MAC computation and verification.
test_name="mac_computation_and_verification"
echo "+++ Starting test $test_name..."

##### Run computation.
$MAC_CLI compute $KEYSET_FILE $DATA_FILE $MAC_FILE

##### Run verification.
test_command $MAC_CLI verify $KEYSET_FILE $DATA_FILE $MAC_FILE

if [[ $TEST_STATUS -eq 0 ]]; then
  echo "+++ Success: MAC computation was successful."
else
  echo "--- Failure: MAC computation was unsuccessful"
  exit 1
fi


#############################################################################
#### Test MAC verification fails with incorrect MAC.
test_name="mac_verification_fails_with_incorrect_mac"
echo "+++ Starting test $test_name..."

##### Run computation.
$MAC_CLI compute $KEYSET_FILE $DATA_FILE $MAC_FILE

# Modify MAC.
echo "DEADBEEF" >> "$MAC_FILE"

##### Run verification.
test_command $MAC_CLI verify $KEYSET_FILE $DATA_FILE $MAC_FILE

if [[ $TEST_STATUS -ne 0 ]]; then
  echo "+++ Success: MAC verification failed for a modified mac."
else
  echo "--- Failure: MAC verification passed for a modified mac."
  exit 1
fi


#############################################################################
#### Test MAC verification fails with modified message.
test_name="mac_verification_fails_with_modified_message"
echo "+++ Starting test $test_name..."

##### Run computation.
$MAC_CLI compute $KEYSET_FILE $DATA_FILE $MAC_FILE

# Modify MAC.
echo "modified" >> "$DATA_FILE"

##### Run verification.
test_command $MAC_CLI verify $KEYSET_FILE $DATA_FILE $MAC_FILE

if [[ $TEST_STATUS -ne 0 ]]; then
  echo "+++ Success: MAC verification failed for a modified message."
else
  echo "--- Failure: MAC verification passed for a modified message."
  exit 1
fi


#############################################################################
#### Test bad key MAC computation.
test_name="bad_key_computation"
echo "+++ Starting test $test_name..."

##### Create a plaintext and bad keyset.
BAD_KEY_FILE="$TEST_TMPDIR/bad_key.txt"
echo "not a key" > $BAD_KEY_FILE

##### Run computation.
test_command $MAC_CLI compute $BAD_KEY_FILE $DATA_FILE $MAC_FILE

if [[ $TEST_STATUS -ne 0 ]]; then
  echo "+++ Success: MAC computation failed with bad keyset."
else
  echo "--- Failure: MAC computation did not fail with bad keyset"
  exit 1
fi
