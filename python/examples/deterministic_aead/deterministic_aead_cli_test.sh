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
# Tests for Deterministic AEAD example.
#############################################################################

CLI="$1"
KEYSET_FILE="$2"

DATA_FILE="${TEST_TMPDIR}/example_data.txt"

echo "This is some plaintext to be encrypted." > "${DATA_FILE}"

#############################################################################

# A helper function for getting the return code of a command that may fail
# Temporarily disables error safety and stores return value in ${TEST_STATUS}
# Usage:
# % test_command somecommand some args
# % echo ${TEST_STATUS}
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

print_test "encrypt"

# Run encryption
test_command ${CLI} --mode encrypt --keyset_path "${KEYSET_FILE}" \
  --input_path "${DATA_FILE}" --output_path "${DATA_FILE}.encrypted"

if (( TEST_STATUS == 0 )); then
  echo "+++ Success: file was encrypted."
else
  echo "--- Failure: could not encrypt file."
  exit 1
fi

#############################################################################

print_test "decrypt"

# Run decryption
test_command ${CLI} --mode decrypt --keyset_path "${KEYSET_FILE}" \
  --input_path "${DATA_FILE}.encrypted" --output_path "${DATA_FILE}.decrypted"

if (( TEST_STATUS == 0 )); then
  echo "+++ Success: file was successfully decrypted."
else
  echo "--- Failure: could not decrypt file."
  exit 1
fi

if cmp -s "${DATA_FILE}" "$DATA_FILE.decrypted"; then
  echo "+++ Success: file content is the same after decryption."
else
  echo "--- Failure: file content is not the same after decryption."
  exit 1
fi

#############################################################################

print_test "encrypt_is_deterministically"

# Run encryption two times
test_command ${CLI} --mode encrypt --keyset_path "${KEYSET_FILE}" \
  --input_path "${DATA_FILE}" --output_path "${DATA_FILE}.encrypted1"

test_command ${CLI} --mode encrypt --keyset_path "${KEYSET_FILE}" \
  --input_path "${DATA_FILE}" --output_path "${DATA_FILE}.encrypted2"

if cmp -s "${DATA_FILE}.encrypted1" "${DATA_FILE}.encrypted2"; then
  echo "+++ Success: ciphertext is the same."
else
  echo "--- Failure: ciphertext is different."
  exit 1
fi

#############################################################################

print_test "test_encrypt_decrypt_fails_with_modified_ciphertext"

# Run encryption
test_command ${CLI} --mode encrypt --keyset_path "${KEYSET_FILE}" \
  --input_path "${DATA_FILE}" --output_path "${DATA_FILE}.encrypted"

if (( TEST_STATUS == 0 )); then
  echo "+++ Encryption successful."
else
  echo "--- Encryption failed."
  exit 1
fi

# Modify ciphertext
echo "modified" >> "${DATA_FILE}.encrypted"

# Run decryption
test_command ${CLI} --mode decrypt --keyset_path "${KEYSET_FILE}" \
  --input_path "${DATA_FILE}.encrypted" --output_path "${DATA_FILE}.decrypted"

if (( TEST_STATUS == 1 )); then
  echo "+++ Decryption failed as expected."
else
  echo "--- Decryption succeeded but expected to fail."
  exit 1
fi

#############################################################################

print_test "test_encrypt_decrypt_succeeds_with_associated_data"

# Run encryption
ASSOCIATED_DATA="header information"
test_command ${CLI} --mode encrypt --keyset_path "${KEYSET_FILE}" \
  --input_path "${DATA_FILE}" --output_path "${DATA_FILE}.encrypted" \
  --associated_data "${ASSOCIATED_DATA}"

if (( TEST_STATUS == 0 )); then
  echo "+++ Encryption successful."
else
  echo "--- Encryption failed."
  exit 1
fi

# Run decryption
test_command ${CLI} --mode decrypt --keyset_path "${KEYSET_FILE}" \
  --input_path "${DATA_FILE}.encrypted" --output_path "${DATA_FILE}.decrypted" \
  --associated_data "${ASSOCIATED_DATA}"

if (( TEST_STATUS == 0 )); then
  echo "+++ Decryption successful."
else
  echo "--- Decryption failed."
  exit 1
fi

cmp --silent "${DATA_FILE}" "${DATA_FILE}.decrypted"

#############################################################################

print_test "test_encrypt_decrypt_fails_with_modified_associated_data"

# Run encryption
ASSOCIATED_DATA="header information"
test_command ${CLI} --mode encrypt --keyset_path "${KEYSET_FILE}" \
  --input_path "${DATA_FILE}" --output_path "${DATA_FILE}.encrypted" \
  --associated_data "${ASSOCIATED_DATA}"

if (( TEST_STATUS == 0 )); then
  echo "+++ Encryption successful."
else
  echo "--- Encryption failed."
  exit 1
fi

# Run decryption
MODIFIED_ASSOCIATED_DATA="modified header information"
test_command ${CLI} --mode decrypt --keyset_path "${KEYSET_FILE}" \
  --input_path "${DATA_FILE}.encrypted" --output_path "${DATA_FILE}.decrypted" \
  --associated_data "${MODIFIED_ASSOCIATED_DATA}"

if (( TEST_STATUS == 1 )); then
  echo "+++ Decryption failed as expected."
else
  echo "--- Decryption succeeded but expected to fail."
  exit 1
fi
