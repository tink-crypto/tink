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
##### Tests for digital signature Java example.

FILE_SIGN_CLI="$1"
KEYSET_FILE_PRIVATE="$2"
KEYSET_FILE_PUBLIC="$3"

SIGNED_TOKEN_FILE="$TEST_TMPDIR/signed_token.txt"

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
test_command $FILE_SIGN_CLI sign $KEYSET_FILE_PRIVATE example_subject $SIGNED_TOKEN_FILE

##### Run verification
test_command $FILE_SIGN_CLI verify $KEYSET_FILE_PUBLIC example_subject $SIGNED_TOKEN_FILE

if [[ $TEST_STATUS -eq 0 ]]; then
  echo "+++ Success: JWT is valid."
else
  echo "--- Failure: JWT is invalid."
  exit 1
fi

#############################################################################
#### Test verification fails with incorrect signature.
test_name="signature_verification_fails_with_incorrect_signature"
echo "+++ Starting test $test_name..."

##### Create a wrong signature.
echo "ABCABCABCD" > $SIGNED_TOKEN_FILE

##### Run verification.
test_command $FILE_SIGN_CLI verify $KEYSET_FILE_PUBLIC example_subject $SIGNED_TOKEN_FILE

if [[ $TEST_STATUS -ne 0 ]]; then
  echo "+++ Success: JWT verification failed for invalid signature."
else
  echo "--- Failure: JWT verification passed for an invalid signature."
  exit 1
fi


#############################################################################
#### Test verification fails with an incorrect data.
test_name="signature_verification_fails_with_incorrect_data"
echo "+++ Starting test $test_name..."

##### Run signing
test_command $FILE_SIGN_CLI sign $KEYSET_FILE_PRIVATE example_subject $SIGNED_TOKEN_FILE

##### Run verification.
test_command $FILE_SIGN_CLI verify $KEYSET_FILE_PUBLIC unknown_subject $SIGNED_TOKEN_FILE

if [[ $TEST_STATUS -ne 0 ]]; then
  echo "+++ Success: JWT verification failed for invalid subject."
else
  echo "--- Failure: JWT verification passed for an invalid subject."
  exit 1
fi


#############################################################################
#### Test signing fails with a wrong keyset.
test_name="singing_fails_with_a_wrong_keyset"
echo "+++ Starting test $test_name..."

##### Run computation.
test_command $FILE_SIGN_CLI sign $KEYSET_FILE_PUBLIC example_subject $SIGNED_TOKEN_FILE

if [[ $TEST_STATUS -ne 0 ]]; then
  echo "+++ Success: JWT computation failed with public keyset."
else
  echo "--- Failure: JWT computation did not fail with public keyset."
  exit 1
fi
