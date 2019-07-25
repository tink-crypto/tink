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


ROOT_DIR="$TEST_SRCDIR/tink"
CC_AEAD_CLI="$ROOT_DIR/tools/testing/cc/aead_cli_cc"
PY2_AEAD_CLI="" # placeholder, please ignore
PY3_AEAD_CLI="" # placeholder, please ignore
GO_AEAD_CLI="$ROOT_DIR/tools/testing/go/aead_cli_go"
JAVA_AEAD_CLI="$ROOT_DIR/tools/testing/aead_cli_java"
TEST_UTIL="$ROOT_DIR/tools/testing/cross_language/test_util.sh"
RUN_EXTERNAL_TESTS=true

# TODO(b/136245485): Update this script to use go/gbash.
# Tests that require external resources cannot run on RBE. If the
# --no_external_tests flag is specified disable these test cases.
if [ "$1" == "--no_external_tests" ]; then
  RUN_EXTERNAL_TESTS=false
fi

source $TEST_UTIL || exit 1

#############################################################################
### Helpers for AEAD-tests.

# Basic tests of AEAD-implementations.
aead_basic_test() {
  local test_name="aead-basic-test"
  local encrypt_clis=$1
  local decrypt_clis=$2
  local key_templates=$3

  echo "############ starting test $test_name for the following templates:"
  echo $key_templates
  for key_template in ${key_templates[*]}
  do
    echo "## TEST for key template $key_template"
    for encrypt_cli in ${encrypt_clis[*]}
    do
      local encrypt_cli_name=$(basename $encrypt_cli)
      echo "## ENCRYPTING using $encrypt_cli_name"
      local test_instance="${test_name}_${key_template}"
      generate_symmetric_key "${test_instance}_ENCRYPT_${encrypt_cli_name}" \
          $key_template
      generate_plaintext $test_instance

      local encrypted_file="$TEST_TMPDIR/${test_instance}_ENCRYPT_${encrypt_cli_name}_encrypted.bin"
      local associated_data_file="$TEST_TMPDIR/${test_instance}_ENCRYPT_${encrypt_cli_name}_aad.bin"
      echo "some associated data for $test_instance using $encrypt_cli_name" \
           "for encryption" > $associated_data_file

      $encrypt_cli $symmetric_key_file "encrypt" $plaintext_file\
          $associated_data_file $encrypted_file|| exit 1
      assert_files_different $plaintext_file $encrypted_file
      for decrypt_cli in ${decrypt_clis[*]}
      do
        local decrypt_cli_name=$(basename "$decrypt_cli")
        local decrypted_file="$TEST_TMPDIR/${test_instance}_ENCRYPT_${encrypt_cli_name}_DECRYPT_${decrypt_cli_name}_decrypted.bin"
        echo "## DECRYPTING using $decrypt_cli_name"
        $decrypt_cli $symmetric_key_file "decrypt" $encrypted_file\
            $associated_data_file $decrypted_file || exit 1
        assert_files_equal $plaintext_file $decrypted_file
      done
    done
  done
}

#############################################################################
### Helpers for AWS AEAD-tests.

# Envelope encryption tests using AWS KMS AEAD-implementations.
aead_aws_test() {
  local test_name="aead-aws-test"
  local encrypt_clis=$1
  local decrypt_clis=$2
  local key_templates=$3
  # lint placeholder header, please ignore
 # ignore-placeholder1
  # lint placeholder footer, please ignore
  echo "############ starting test $test_name for the following templates:"
  echo $key_templates
  for key_template in ${key_templates[*]}
  do
    echo "## TEST for key template $key_template"
    for encrypt_cli in ${encrypt_clis[*]}
    do
      local encrypt_cli_name=$(basename $encrypt_cli)
      echo "## ENCRYPTING using $encrypt_cli_name"
      local test_instance="${test_name}_${key_template}"
      generate_aws_keyset "${test_instance}_ENCRYPT_${encrypt_cli_name}" \
          $key_template
      generate_plaintext $test_instance 30000

      local encrypted_file="$TEST_TMPDIR/${test_instance}_ENCRYPT_${encrypt_cli_name}_encrypted.bin"
      local associated_data_file="$TEST_TMPDIR/${test_instance}_ENCRYPT_${encrypt_cli_name}_aad.bin"
      echo "some associated data for $test_instance using $encrypt_cli_name" \
          "for encryption" > $associated_data_file

      $encrypt_cli $aws_keyset_file "encrypt" $plaintext_file\
          $associated_data_file $encrypted_file|| exit 1
      assert_files_different $plaintext_file $encrypted_file
      for decrypt_cli in ${decrypt_clis[*]}
      do
        local decrypt_cli_name=$(basename "$decrypt_cli")
        local decrypted_file="$TEST_TMPDIR/${test_instance}_ENCRYPT_${encrypt_cli_name}_DECRYPT_${decrypt_cli_name}_decrypted.bin"
        echo "## DECRYPTING using $decrypt_cli_name"
        $decrypt_cli $aws_keyset_file "decrypt" $encrypted_file\
            $associated_data_file $decrypted_file || exit 1
        assert_files_equal $plaintext_file $decrypted_file
      done
    done
  done
}

#############################################################################
### Helpers for GCP AEAD-tests.

# Envelope encryption tests using GCP KMS AEAD-implementations.
aead_gcp_test() {
  local test_name="aead-gcp-test"
  local encrypt_clis=$1
  local decrypt_clis=$2
  local key_templates=$3
  # lint placeholder header, please ignore
 # ignore-placeholder1
  # lint placeholder footer, please ignore
  echo "############ starting test $test_name for the following templates:"
  echo $key_templates
  for key_template in ${key_templates[*]}
  do
    echo "## TEST for key template $key_template"
    for encrypt_cli in ${encrypt_clis[*]}
    do
      local encrypt_cli_name=$(basename $encrypt_cli)
      echo "## ENCRYPTING using $encrypt_cli_name"
      local test_instance="${test_name}_${key_template}"
      generate_gcp_keyset "${test_instance}_ENCRYPT_${encrypt_cli_name}" \
          $key_template
      generate_plaintext $test_instance 30000

      local encrypted_file="$TEST_TMPDIR/${test_instance}_ENCRYPT_${encrypt_cli_name}_encrypted.bin"
      local associated_data_file="$TEST_TMPDIR/${test_instance}_ENCRYPT_${encrypt_cli_name}_aad.bin"
      echo "some associated data for $test_instance using $encrypt_cli_name" \
          "for encryption" > $associated_data_file
      $encrypt_cli $gcp_keyset_file "encrypt" $plaintext_file\
        $associated_data_file $encrypted_file || exit 1
      assert_files_different $plaintext_file $encrypted_file

      for decrypt_cli in ${decrypt_clis[*]}
      do
        local decrypt_cli_name=$(basename "$decrypt_cli")
        local decrypted_file="$TEST_TMPDIR/${test_instance}_ENCRYPT_${encrypt_cli_name}_DECRYPT_${decrypt_cli_name}_decrypted.bin"
        echo "## DECRYPTING using $decrypt_cli_name"
        $decrypt_cli $gcp_keyset_file "decrypt" $encrypted_file\
           $associated_data_file $decrypted_file || exit 1
        assert_files_equal $plaintext_file $decrypted_file
      done
    done
  done
}

#############################################################################
##### Run the actual tests.
KEY_TEMPLATES=(AES128_GCM AES256_GCM AES128_CTR_HMAC_SHA256 AES256_CTR_HMAC_SHA256)
ENCRYPT_CLIS=($CC_AEAD_CLI $JAVA_AEAD_CLI $GO_AEAD_CLI $PY2_AEAD_CLI $PY3_AEAD_CLI)
DECRYPT_CLIS=($CC_AEAD_CLI $JAVA_AEAD_CLI $GO_AEAD_CLI $PY2_AEAD_CLI $PY3_AEAD_CLI)
aead_basic_test "${ENCRYPT_CLIS[*]}" "${DECRYPT_CLIS[*]}" "${KEY_TEMPLATES[*]}"

KEY_TEMPLATES=(AES128_EAX AES256_EAX)
ENCRYPT_CLIS=($CC_AEAD_CLI $JAVA_AEAD_CLI $PY2_AEAD_CLI $PY3_AEAD_CLI)
DECRYPT_CLIS=($CC_AEAD_CLI $JAVA_AEAD_CLI $PY2_AEAD_CLI $PY3_AEAD_CLI)
aead_basic_test "${ENCRYPT_CLIS[*]}" "${DECRYPT_CLIS[*]}" "${KEY_TEMPLATES[*]}"

if [ "$RUN_EXTERNAL_TESTS" = true ]; then
  KEY_TEMPLATES=(AES128_GCM AES128_CTR_HMAC_SHA256)
  ENCRYPT_CLIS=($GO_AEAD_CLI $JAVA_AEAD_CLI)
  DECRYPT_CLIS=($GO_AEAD_CLI $JAVA_AEAD_CLI)
  aead_gcp_test "${ENCRYPT_CLIS[*]}" "${DECRYPT_CLIS[*]}" "${KEY_TEMPLATES[*]}"

  # lint placeholder header, please ignore
  aead_aws_test "${ENCRYPT_CLIS[*]}" "${DECRYPT_CLIS[*]}" "${KEY_TEMPLATES[*]}"

  # lint placeholder footer, please ignore
fi
