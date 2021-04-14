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
##### Tests for digital signature example.

FILE_SIGN_CLI="$1"
KEYSET_FILE_PRIVATE="$2"
KEYSET_FILE_PUBLIC="$3"

DATA_FILE="$TEST_TMPDIR/example_data.txt"
SIGNATURE_FILE="$TEST_TMPDIR/expected_signature.txt"

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
#### Test basic signature signing and verification.
test_name="normal_signing_and_verification"
echo "+++ Starting test $test_name..."

##### Run signing
test_command $FILE_SIGN_CLI sign $KEYSET_FILE_PRIVATE $DATA_FILE $SIGNATURE_FILE

##### Run verification
test_command $FILE_SIGN_CLI verify $KEYSET_FILE_PUBLIC $DATA_FILE $SIGNATURE_FILE

if [[ $TEST_STATUS -eq 0 ]]; then
  echo "+++ Success: Signature is valid."
else
  echo "--- Failure: the Signature is invalid."
  exit 1
fi

#############################################################################
#### Test verification fails with incorrect signature.
test_name="signature_verification_fails_with_incorrect_signature"
echo "+++ Starting test $test_name..."

##### Create a wrong signature.
echo "ABCABCABCD" > $SIGNATURE_FILE

##### Run verification.
test_command $FILE_SIGN_CLI verify $KEYSET_FILE_PUBLIC $DATA_FILE $SIGNATURE_FILE

if [[ $TEST_STATUS -ne 0 ]]; then
  echo "+++ Success: Signature verification failed for invalid signature."
else
  echo "--- Failure: Signature passed for an invalid signature."
  exit 1
fi


#############################################################################
#### Test verification fails with an incorrect data.
test_name="signature_verification_fails_with_incorrect_data"
echo "+++ Starting test $test_name..."

##### Run signing
test_command $FILE_SIGN_CLI sign $KEYSET_FILE_PRIVATE $DATA_FILE $SIGNATURE_FILE

##### Modify the data.
echo "ABCABCABCD" >> $DATA_FILE

##### Run verification.
test_command $FILE_SIGN_CLI verify $KEYSET_FILE_PUBLIC $DATA_FILE $SIGNATURE_FILE

if [[ $TEST_STATUS -ne 0 ]]; then
  echo "+++ Success: Signature verification failed for invalid signature."
else
  echo "--- Failure: Signature passed for an invalid signature."
  exit 1
fi


#############################################################################
#### Test signing fails with a wrong keyset.
test_name="singing_fails_with_a_wrong_keyset"
echo "+++ Starting test $test_name..."

##### Run computation.
test_command $FILE_SIGN_CLI sign $KEYSET_FILE_PUBLIC $DATA_FILE $SIGNATURE_FILE

if [[ $TEST_STATUS -ne 0 ]]; then
  echo "+++ Success: Signature computation failed with public keyset."
else
  echo "--- Failure: Signature computation did not fail with public keyset."
  exit 1
fi
