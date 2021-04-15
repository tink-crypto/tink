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
# Tests for hybrid encryption example.
#############################################################################

CLI="$1"
PUBLIC_KEYSET_FILE="$2"
PRIVATE_KEYSET_FILE="$3"

INPUT_FILE="${TEST_TMPDIR}/example_data.txt"

echo "This is some message to be encrypted." > "${INPUT_FILE}"

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

print_test "test_encrypt_decrypt_succeeds"

# Run encryption
test_command ${CLI} --mode=encrypt --keyset_path="${PUBLIC_KEYSET_FILE}" \
    --input_path="${INPUT_FILE}" --output_path="${INPUT_FILE}.ciphertext"

if (( TEST_STATUS == 0 )); then
  echo "+++ Encryption successful."
else
  echo "--- Encryption failed."
  exit 1
fi

# Run decryption
test_command ${CLI} --mode=decrypt --keyset_path="${PRIVATE_KEYSET_FILE}" \
    --input_path="${INPUT_FILE}.ciphertext" --output_path="${INPUT_FILE}.plaintext"

if (( TEST_STATUS == 0 )); then
  echo "+++ Decryption successful."
else
  echo "--- Decryption failed."
  exit 1
fi

cat "${INPUT_FILE}"
cat "${INPUT_FILE}.plaintext"
cmp --silent "${INPUT_FILE}" "${INPUT_FILE}.plaintext"


#############################################################################

print_test "test_encrypt_decrypt_succeeds_with_context"

# Run encryption
CONTEXT_INFORMATION="context information"
test_command ${CLI} --mode=encrypt --context_info="${CONTEXT_INFORMATION}" \
    --keyset_path="${PUBLIC_KEYSET_FILE}" --input_path="${INPUT_FILE}" \
    --output_path="${INPUT_FILE}.ciphertext"

if (( TEST_STATUS == 0 )); then
  echo "+++ Encryption successful."
else
  echo "--- Encryption failed."
  exit 1
fi

# Run decryption
test_command ${CLI} --mode=decrypt --context_info="${CONTEXT_INFORMATION}" \
    --keyset_path="${PRIVATE_KEYSET_FILE}" --input_path="${INPUT_FILE}.ciphertext" \
    --output_path="${INPUT_FILE}.plaintext"

if (( TEST_STATUS == 0 )); then
  echo "+++ Decryption successful."
else
  echo "--- Decryption failed."
  exit 1
fi

cmp --silent "${INPUT_FILE}" "${INPUT_FILE}.plaintext"

#############################################################################

print_test "test_encrypt_decrypt_fails_with_context"

# Run encryption
CONTEXT_INFORMATION="context information"
test_command ${CLI} --mode=encrypt --context_info="${CONTEXT_INFORMATION}" \
    --keyset_path="${PUBLIC_KEYSET_FILE}" --input_path="${INPUT_FILE}" \
    --output_path="${INPUT_FILE}.ciphertext"

if (( TEST_STATUS == 0 )); then
  echo "+++ Encryption successful."
else
  echo "--- Encryption failed."
  exit 1
fi

# Run decryption
test_command ${CLI} --mode=decrypt --keyset_path="${PRIVATE_KEYSET_FILE}" \
    --input_path="${INPUT_FILE}.ciphertext" --output_path="${INPUT_FILE}.plaintext"

if (( TEST_STATUS == 1 )); then
  echo "+++ Decryption failed as expected."
else
  echo "--- Decryption succeeded but expected to fail."
  exit 1
fi

#############################################################################

print_test "test_encrypt_fails_with_wrong_keyset"

# Run encryption
test_command ${CLI} --mode=encrypt --keyset_path="${PRIVATE_KEYSET_FILE}" \
    --input_path="${INPUT_FILE}" --output_path="${INPUT_FILE}.ciphertext"

if (( TEST_STATUS == 1 )); then
  echo "+++ Encryption failed as expected."
else
  echo "--- Encryption succeeded but expected to fail."
  exit 1
fi
