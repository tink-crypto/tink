#!/bin/bash
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
##### Tests for file_mac python example.

FILE_SIGN_CLI="$1"
KEYSET_FILE_PRIVATE="$2"
KEYSET_FILE_PUBLIC="$3"

DATA_FILE="$TEST_TMPDIR/example_data.txt"
EXPECTED_SIGNATURE_FILE="$TEST_TMPDIR/expected_signature.txt"

echo "This is some message to be verified." > $DATA_FILE
CORRECT_SIGNATURE="01622abd92012330a2de153af7db5f3097d61dcc55c678215c1f6b871509d52e7a37fb038ca14879cc47f5ee11409f63dc24bc38d5ca2272ababc0d24a164438a80cb4db00"

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
#### Test good key and correct signature verification.
test_name="normal_verification"
echo "+++ Starting test $test_name..."

##### Create a plaintext and actual MAC.
echo "$CORRECT_SIGNATURE" > $EXPECTED_SIGNATURE_FILE

##### Run verification
test_command $FILE_SIGN_CLI verify $KEYSET_FILE_PUBLIC $DATA_FILE $EXPECTED_SIGNATURE_FILE

if [[ $TEST_STATUS -eq 0 ]]; then
  echo "+++ Success: Signature is valid."
else
  echo "--- Failure: the Signature is invalid."
  exit 1
fi


#############################################################################
#### Test good key and incorrect Signature verification.
test_name="incorrect_signature_verification"
echo "+++ Starting test $test_name..."

##### Create a plaintext and wrong signature.
echo "ABCABCABCD" > $EXPECTED_SIGNATURE_FILE

##### Run verification.
test_command $FILE_SIGN_CLI verify $KEYSET_FILE_PUBLIC $DATA_FILE $EXPECTED_SIGNATURE_FILE

if [[ $TEST_STATUS -ne 0 ]]; then
  echo "+++ Success: Signature verification failed for invalid signature."
else
  echo "--- Failure: Signature passed for an invalid signature."
  exit 1
fi


#############################################################################
#### Test good key signature computation.
test_name="signature_computation"
echo "+++ Starting test $test_name..."

##### Create a plaintext and actual signature.
SIGNATURE_OUTPUT_FILE="$TEST_TMPDIR/computed_signature_log.txt"

##### Run computation.
$FILE_SIGN_CLI sign $KEYSET_FILE_PRIVATE $DATA_FILE --alsologtostderr 2> $SIGNATURE_OUTPUT_FILE
##### Check that the correct signature was produced in the logs
test_command grep --quiet --ignore-case "$CORRECT_SIGNATURE" "$SIGNATURE_OUTPUT_FILE"

if [[ $TEST_STATUS -eq 0 ]]; then
  echo "+++ Success: Signature computation was successful."
else
  echo "--- Failure: Signature computation was unsuccessful"
  exit 1
fi


#############################################################################
#### Test Signature computation with wrong keyset.
test_name="public_key_computation"
echo "+++ Starting test $test_name..."

##### Run computation.
test_command $FILE_SIGN_CLI sign $KEYSET_FILE_PUBLIC $DATA_FILE

if [[ $TEST_STATUS -ne 0 ]]; then
  echo "+++ Success: Signature computation failed with public keyset."
else
  echo "--- Failure: Signature computation did not fail with public keyset."
  exit 1
fi
