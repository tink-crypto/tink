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
##### Tests for streaming_aead python example.

HYBRID_ENCRYPTION_CLI="$1"
PUBLIC_KEYSET_FILE="$2"

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
test_name="test_encrypt_succeeds"
echo "+++ Starting test ${test_name}..."

##### Run verification
test_command ${HYBRID_ENCRYPTION_CLI} --keyset_path=${PUBLIC_KEYSET_FILE} --input_path=${INPUT_FILE} --output_path=${INPUT_FILE}.ciphertext
if [[ ${TEST_STATUS} -eq 0 ]]; then
  echo "+++ Encryption successful."
else
  echo "--- Encryption failed."
  exit 1
fi


#############################################################################
#### Test correct encryption with context
test_name="test_encrypt_succeeds_with_context"
echo "+++ Starting test ${test_name}..."

##### Run verification
CONTEXT_INFORMATION="context information"
test_command ${HYBRID_ENCRYPTION_CLI} --context_info=${CONTEXT_INFORMATION} --keyset_path=${PUBLIC_KEYSET_FILE} --input_path=${INPUT_FILE} --output_path=${INPUT_FILE}.ciphertext
if [[ ${TEST_STATUS} -eq 0 ]]; then
  echo "+++ Encryption successful."
else
  echo "--- Encryption failed."
  exit 1
fi
