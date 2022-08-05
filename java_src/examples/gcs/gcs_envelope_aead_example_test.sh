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
##### Tests for envelope encryption AEAD example.

CLI="$1"
KEY_URI="$2"
CRED_FILE="$3"
PROJECT_ID="$4"
GCS_BUCKET="$5"

DATA_FILE="$TEST_TMPDIR/example_data.txt"

echo "This is some plaintext to be encrypted." > ${DATA_FILE}

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

#############################################################################
#### Test initialization and encryption
test_name="encrypt"
echo "+++ Starting test $test_name..."

# ##### Run encryption
test_command ${CLI} encrypt ${KEY_URI} ${CRED_FILE} ${PROJECT_ID} \
    ${DATA_FILE} "${GCS_BUCKET}/example_data.txt.encrypted"

if [[ ${TEST_STATUS} -eq 0 ]]; then
  echo "+++ Success: file was encrypted."
else
  echo "--- Failure: could not encrypt file."
  exit 1
fi

#############################################################################
#### Test if decryption succeeds and returns original file
test_name="decrypt"
echo "+++ Starting test $test_name..."

##### Run decryption
test_command ${CLI} decrypt ${KEY_URI} ${CRED_FILE} ${PROJECT_ID} \
    "${GCS_BUCKET}/example_data.txt.encrypted" "${DATA_FILE}.decrypted"

if [[ ${TEST_STATUS} -eq 0 ]]; then
  echo "+++ Success: file was successfully decrypted."
else
  echo "--- Failure: could not decrypt file."
  exit 1
fi

if cmp -s ${DATA_FILE} "${DATA_FILE}.decrypted"; then
  echo "+++ Success: file content is the same after decryption."
else
  echo "--- Failure: file content is not the same after decryption."
  exit 1
fi
