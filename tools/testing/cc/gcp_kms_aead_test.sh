#!/bin/bash
# Copyright 2019 Google LLC
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

REPO_DIR="${TEST_SRCDIR}"
TOOLS_DIR="${REPO_DIR}/tools"
GCP_KMS_AEAD_CLI="${TOOLS_DIR}/testing/cc/gcp_kms_aead_cli"
TEST_UTIL="${TOOLS_DIR}/testing/cross_language/test_util.sh"
GCP_KEY_NAME_FILE="${TOOLS_DIR}/testdata/gcp_key_name.txt"
CREDENTIALS_GCP_JSON_FILE="${TOOLS_DIR}/testdata/credential.json"
BAD_GCP_KEY_NAME_FILE="${TOOLS_DIR}/testdata/bad_gcp_key_name.txt"
BAD_CREDENTIALS_GCP_JSON_FILE="${TOOLS_DIR}/testdata/bad_gcp_credentials.json"
associated_data="some associated data"

# Roots for GRPC
# (https://github.com/grpc/grpc/blob/master/doc/environment_variables.md)
export GRPC_DEFAULT_SSL_ROOTS_FILE_PATH="$TEST_SRCDIR/google_root_pem/file/downloaded"

source $TEST_UTIL || exit 1

#############################################################################
# All good, encryption and decryption should work.
test_name="good_key_name_and_credentials"
echo "+++ starting test $test_name ..."
generate_plaintext $test_name
encrypted_file="$TEST_TMPDIR/${test_name}_encrypted.bin"
decrypted_file="$TEST_TMPDIR/${test_name}_decrypted.bin"
log_file="$TEST_TMPDIR/${test_name}.log"
echo "    encrypting..."
$GCP_KMS_AEAD_CLI $GCP_KEY_NAME_FILE $CREDENTIALS_GCP_JSON_FILE\
  encrypt $plaintext_file "$associated_data" $encrypted_file 2> $log_file
assert_file_contains $log_file "All done"
assert_files_different $plaintext_file $encrypted_file

echo "    decrypting..."
$GCP_KMS_AEAD_CLI $GCP_KEY_NAME_FILE $CREDENTIALS_GCP_JSON_FILE\
  decrypt $encrypted_file "$associated_data" $decrypted_file 2> $log_file
assert_file_contains $log_file "All done"

echo "    checking decryption result..."
assert_files_equal $plaintext_file $decrypted_file

#############################################################################
# Bad credentials test.
test_name="bad_gcp_credentials"
echo "+++ starting test $test_name ..."
generate_plaintext $test_name
encrypted_file="$TEST_TMPDIR/${test_name}_encrypted.bin"
log_file="$TEST_TMPDIR/${test_name}.log"
$GCP_KMS_AEAD_CLI $GCP_KEY_NAME_FILE $BAD_CREDENTIALS_GCP_JSON_FILE\
  encrypt $plaintext_file "$associated_data" $encrypted_file 2> $log_file

assert_file_contains $log_file "invalid authentication credentials"

#############################################################################
# Bad key name test.
test_name="bad_key_name"
echo "+++ starting test $test_name ..."
generate_plaintext $test_name
encrypted_file="$TEST_TMPDIR/${test_name}_encrypted.bin"
log_file="$TEST_TMPDIR/${test_name}.log"
$GCP_KMS_AEAD_CLI $BAD_GCP_KEY_NAME_FILE $CREDENTIALS_GCP_JSON_FILE\
  encrypt $plaintext_file "$associated_data" $encrypted_file 2> $log_file

assert_file_contains $log_file "Permission" "denied" "or it may not exist"
