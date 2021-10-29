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

SIGN_CLI="$1"
GEN_PUBLIC_JWK_SET_CLI="$2"
VERIFY_CLI="$3"
PRIVATE_KEYSET_PATH="$4"

AUDIENCE="audience"
TOKEN_PATH="${TEST_TMPDIR}/token.txt"
PUBLIC_JWK_SET_PATH="${TEST_TMPDIR}/public_jwk_set.json"

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
#### Test generate token
test_name="generate_token"
echo "+++ Starting test $test_name..."

test_command ${SIGN_CLI} ${PRIVATE_KEYSET_PATH} ${AUDIENCE} ${TOKEN_PATH}

if [[ $TEST_STATUS -eq 0 ]]; then
  echo "+++ Success: Generating the token succeeded."
else
  echo "--- Failure: Generating the token failed."
  exit 1
fi

#############################################################################
#### Test generate public JWK Set
test_name="generate_public_jwk_set"
echo "+++ Starting test $test_name..."

test_command ${GEN_PUBLIC_JWK_SET_CLI} ${PRIVATE_KEYSET_PATH} ${PUBLIC_JWK_SET_PATH}

if [[ $TEST_STATUS -eq 0 ]]; then
  echo "+++ Success: Generating the public JWK set succeeded."
else
  echo "--- Failure: Generating the public JWK set failed."
  exit 1
fi

#############################################################################
##### Test verification
test_name="token_verification_success"
echo "+++ Starting test $test_name..."

test_command ${VERIFY_CLI} ${PUBLIC_JWK_SET_PATH} ${AUDIENCE} ${TOKEN_PATH}

if [[ $TEST_STATUS -eq 0 ]]; then
  echo "+++ Success: Verification passed for a valid token."
else
  echo "--- Failure: Verification failed for a valid token."
  exit 1
fi

#############################################################################
#### Test verification fails with invalid token.
test_name="token_verification_fails_with_invalid_token"
echo "+++ Starting test $test_name..."

##### Create an invalid token.
INVALID_TOKEN_PATH="${TEST_TMPDIR}/invalid_token.txt"
echo "ABCABCABCD" > $INVALID_TOKEN_PATH

##### Run verification.
test_command ${VERIFY_CLI} ${PUBLIC_JWK_SET_PATH} ${AUDIENCE} ${INVALID_TOKEN_PATH}

if [[ $TEST_STATUS -ne 0 ]]; then
  echo "+++ Success: Verification failed with invalid token."
else
  echo "--- Failure: Verification passed with invalid token."
  exit 1
fi


#############################################################################
#### Test verification fails with an invalid audience.
test_name="token_verification_fails_with_invalid_audience"
echo "+++ Starting test $test_name..."

test_command ${VERIFY_CLI} $PUBLIC_JWK_SET_PATH unknown_audience ${TOKEN_PATH}

if [[ $TEST_STATUS -ne 0 ]]; then
  echo "+++ Success: Verification failed for an invalid audience."
else
  echo "--- Failure: Verification passed for an invalid audience."
  exit 1
fi


#############################################################################
#### Test signing fails with invalid keyset.
test_name="generating_token_fails_with_invalid_keyset"
echo "+++ Starting test $test_name..."

test_command ${SIGN_CLI} ${PUBLIC_JWK_SET_PATH} ${AUDIENCE} ${TOKEN_PATH}

if [[ $TEST_STATUS -ne 0 ]]; then
  echo "+++ Success: Generating a token failed with invalid keyset."
else
  echo "--- Failure: Generating a token did not fail with invalid keyset."
  exit 1
fi


#############################################################################
#### Test verification fails with invalid keyset.
test_name="verify_fails_with_a_invalid_keyset"
echo "+++ Starting test $test_name..."

test_command ${VERIFY_CLI} ${PRIVATE_KEYSET_PATH} ${AUDIENCE} ${TOKEN_PATH}

if [[ $TEST_STATUS -ne 0 ]]; then
  echo "+++ Success: Verification failed with invalid keyset."
else
  echo "--- Failure: Verification did not fail with invalid keyset."
  exit 1
fi
