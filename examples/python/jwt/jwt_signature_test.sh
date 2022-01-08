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

print_test() {
  echo "+++ Starting test $1..."
}


#############################################################################

print_test "generate_token"

# Generate a signed token
test_command ${SIGN_CLI} \
  --keyset_path "${PRIVATE_KEYSET_PATH}" \
  --audience "${AUDIENCE}" \
  --token_path "${TOKEN_PATH}"

if (( TEST_STATUS == 0 )); then
  echo "+++ Success: Generating the token succeeded."
else
  echo "--- Failure: Generating the token failed."
  exit 1
fi

#############################################################################

print_test "generate_public_keyset"

# Generate the public keyset in JWK format
test_command ${GEN_PUBLIC_JWK_SET_CLI} \
  --keyset_path "${PRIVATE_KEYSET_PATH}" \
  --public_jwk_set_path "${PUBLIC_JWK_SET_PATH}"

if (( TEST_STATUS == 0 )); then
  echo "+++ Success: Generating the public JWK set succeeded."
else
  echo "--- Failure: Generating the public JWK set failed."
  exit 1
fi

#############################################################################

print_test "normal_verification"

# Verify the token
test_command ${VERIFY_CLI} \
  --public_jwk_set_path "${PUBLIC_JWK_SET_PATH}" \
  --audience "${AUDIENCE}" \
  --token_path "${TOKEN_PATH}"

if (( TEST_STATUS == 0 )); then
  echo "+++ Success: Verification passed for a valid token."
else
  echo "--- Failure: Verification failed for a valid token."
  exit 1
fi


#############################################################################

print_test "verification_fails_with_invalid_token"

# Create an invalid token.
INVALID_TOKEN_PATH="${TEST_TMPDIR}/invalid_token.txt"
echo "ABCABCABCD" > $INVALID_TOKEN_PATH

# Verify the invalid token
test_command ${VERIFY_CLI} \
  --public_jwk_set_path "${PUBLIC_JWK_SET_PATH}" \
  --audience "${AUDIENCE}" \
  --token_path "${INVALID_TOKEN_PATH}"

if (( TEST_STATUS != 0 )); then
  echo "+++ Success: Verification failed for an invalid token."
else
  echo "--- Failure: Verification passed for an invalid token."
  exit 1
fi


#############################################################################

print_test "verification_fails_with_incorrect_audience"

# Verify the token with an invalid audience
test_command ${VERIFY_CLI} \
  --public_jwk_set_path "${PUBLIC_JWK_SET_PATH}" \
  --audience "invalid audience" \
  --token_path "${TOKEN_PATH}"

if (( TEST_STATUS != 0 )); then
  echo "+++ Success: Verification failed with an invalid audience."
else
  echo "--- Failure: Verification passed with an invalid audience."
  exit 1
fi


#############################################################################

print_test "generating_token_fails_with_invalid_keyset"

# Use a different token path
TOKEN2_PATH="${TEST_TMPDIR}/token2.txt"

# Try to generate a signed token using the public keyset
test_command ${SIGN_CLI} \
  --keyset_path "${PUBLIC_JWK_SET_PATH}" \
  --audience "${AUDIENCE}" \
  --token_path "${TOKEN2_PATH} "

if (( TEST_STATUS != 0 )); then
  echo "+++ Success: Generating a token failed with invalid keyset."
else
  echo "--- Failure: Generating a token did not fail with invalid keyset."
  exit 1
fi


#############################################################################

print_test "verify_fails_with_a_invalid_keyset"

# Try to verify the token using the private key
test_command ${VERIFY_CLI} \
  --public_jwk_set_path "${PRIVATE_KEYSET_PATH}" \
  --audience "${AUDIENCE}" \
  --token_path "${TOKEN_PATH}"

if (( TEST_STATUS != 0 )); then
  echo "+++ Success: Verification failed with invalid keyset."
else
  echo "--- Failure: Verification did not fail with invalid keyset."
  exit 1
fi
