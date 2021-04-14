#!/bin/bash
# Copyright 2020 Google LLC
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
##### Tests for streaming_aead python example.

FILE_STREAMING_AEAD_CLI="$1"
KEYSET_FILE="$2"

INPUT_FILE="${TEST_TMPDIR}/example_data.txt"

echo "This is some message to be encrypted." > ${INPUT_FILE}

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
#### Test correct encryption and decryption.
test_name="test_encrypt_decrypt"
echo "+++ Starting test ${test_name}..."

##### Run verification
test_command ${FILE_STREAMING_AEAD_CLI} --mode=encrypt --keyset_path=${KEYSET_FILE} --input_path=${INPUT_FILE} --output_path=${INPUT_FILE}.ciphertext
if [[ ${TEST_STATUS} -eq 0 ]]; then
  echo "+++ Encryption successful."
else
  echo "--- Encryption failed."
  exit 1
fi

test_command ${FILE_STREAMING_AEAD_CLI} --mode=decrypt --keyset_path=${KEYSET_FILE} --input_path=${INPUT_FILE}.ciphertext --output_path=${INPUT_FILE}.plaintext
if [[ ${TEST_STATUS} -eq 0 ]]; then
  echo "+++ Decryption successful."
else
  echo "--- Decryption failed."
  exit 1
fi

cmp --silent ${INPUT_FILE} ${INPUT_FILE}.plaintext

#############################################################################
#### Test correct encryption and decryption with associated data
test_name="test_encrypt_decrypt_with_ad"
echo "+++ Starting test ${test_name}..."

##### Run verification
HEADER_INFORMATION="header information"
test_command ${FILE_STREAMING_AEAD_CLI} --mode=encrypt --associated_data=${HEADER_INFORMATION} --keyset_path=${KEYSET_FILE} --input_path=${INPUT_FILE} --output_path=${INPUT_FILE}.ciphertext
if [[ ${TEST_STATUS} -eq 0 ]]; then
  echo "+++ Encryption successful."
else
  echo "--- Encryption failed."
  exit 1
fi

test_command ${FILE_STREAMING_AEAD_CLI} --mode=decrypt --associated_data=${HEADER_INFORMATION} --keyset_path=${KEYSET_FILE} --input_path=${INPUT_FILE}.ciphertext --output_path=${INPUT_FILE}.plaintext
if [[ ${TEST_STATUS} -eq 0 ]]; then
  echo "+++ Decryption successful."
else
  echo "--- Decryption failed."
  exit 1
fi

cmp --silent ${INPUT_FILE} ${INPUT_FILE}.plaintext

#############################################################################
#### Test that modified ciphertext does not decrypt
test_name="test_modified_ciphertext"
echo "+++ Starting test ${test_name}..."

##### Run verification
test_command ${FILE_STREAMING_AEAD_CLI} --mode=encrypt --keyset_path=${KEYSET_FILE} --input_path=${INPUT_FILE} --output_path=${INPUT_FILE}.ciphertext
if [[ ${TEST_STATUS} -eq 0 ]]; then
  echo "+++ Encryption successful."
else
  echo "--- Encryption failed."
  exit 1
fi

# Modify ciphertext so it becomes invalid
echo "modification" >> ${INPUT_FILE}.ciphertext

test_command ${FILE_STREAMING_AEAD_CLI} --mode=decrypt --keyset_path=${KEYSET_FILE} --input_path=${INPUT_FILE}.ciphertext --output_path=${INPUT_FILE}.plaintext
if [[ ${TEST_STATUS} -eq 1 ]]; then
  echo "+++ Decryption failed as expected."
else
  echo "--- Decryption successful but expected to fail."
  exit 1
fi
