#!/bin/bash
# Copyright 2018 Google LLC
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
AWS_KMS_AEAD_CLI="${TOOLS_DIR}/testing/cc/aws_kms_aead_cli"
TEST_UTIL="${TOOLS_DIR}/testing/cross_language/test_util.sh"
AWS_KEY_ARN_FILE="${TOOLS_DIR}/testdata/aws_key_arn.txt"
CREDENTIALS_AWS_CSV_FILE="${TOOLS_DIR}/testdata/aws_credentials_cc.txt"
BAD_AWS_KEY_ARN_FILE="${TOOLS_DIR}/testdata/bad_aws_key_arn.txt"
BAD_CREDENTIALS_AWS_CSV_FILE="${TOOLS_DIR}/testdata/bad_aws_credentials_cc.txt"
associated_data="some associated data"

source $TEST_UTIL || exit 1

#############################################################################
# Bad access key test.
test_name="bad_aws_access_key"
echo "+++ starting test $test_name ..."
generate_plaintext $test_name
encrypted_file="$TEST_TMPDIR/${test_name}_encrypted.bin"
log_file="$TEST_TMPDIR/${test_name}.log"
$AWS_KMS_AEAD_CLI $AWS_KEY_ARN_FILE $BAD_CREDENTIALS_AWS_CSV_FILE\
  encrypt $plaintext_file "$associated_data" $encrypted_file 2> $log_file

assert_file_contains $log_file "UnrecognizedClientException"

#############################################################################
# Bad key arn test.
test_name="bad_key_arn"
echo "+++ starting test $test_name ..."
generate_plaintext $test_name
encrypted_file="$TEST_TMPDIR/${test_name}_encrypted.bin"
log_file="$TEST_TMPDIR/${test_name}.log"
$AWS_KMS_AEAD_CLI $BAD_AWS_KEY_ARN_FILE $CREDENTIALS_AWS_CSV_FILE\
  encrypt $plaintext_file "$associated_data" $encrypted_file 2> $log_file

assert_file_contains $log_file "AccessDeniedException"

#############################################################################
# All good, encryption and decryption should work.
test_name="good_key_arn_and_access_key"
echo "+++ starting test $test_name ..."
generate_plaintext $test_name
encrypted_file="$TEST_TMPDIR/${test_name}_encrypted.bin"
decrypted_file="$TEST_TMPDIR/${test_name}_decrypted.bin"
log_file="$TEST_TMPDIR/${test_name}.log"
echo "    encrypting..."
$AWS_KMS_AEAD_CLI $AWS_KEY_ARN_FILE $CREDENTIALS_AWS_CSV_FILE\
  encrypt $plaintext_file "$associated_data" $encrypted_file 2> $log_file
assert_file_contains $log_file "All done"
assert_files_different $plaintext_file $encrypted_file

echo "    decrypting..."
$AWS_KMS_AEAD_CLI $AWS_KEY_ARN_FILE $CREDENTIALS_AWS_CSV_FILE\
  decrypt $encrypted_file "$associated_data" $decrypted_file 2> $log_file
assert_file_contains $log_file "All done"

echo "    checking decryption result..."
assert_files_equal $plaintext_file $decrypted_file
