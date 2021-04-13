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


ROOT_DIR="$TEST_SRCDIR/tools"
CC_AEAD_CLI="$ROOT_DIR/testing/cc/aead_cli_cc"
GO_AEAD_CLI="$ROOT_DIR/testing/go/aead_cli_go"
JAVA_AEAD_CLI="$ROOT_DIR/testing/aead_cli_java"
PY_AEAD_CLI="$ROOT_DIR/testing/python/aead_cli_python"
TEST_UTIL="$ROOT_DIR/testing/cross_language/test_util.sh"

# Roots for GRPC
# (https://github.com/grpc/grpc/blob/master/doc/environment_variables.md)
export GRPC_DEFAULT_SSL_ROOTS_FILE_PATH="$TEST_SRCDIR/google_root_pem/file/downloaded"

source $TEST_UTIL || exit 1

#############################################################################
### Helpers for AWS AEAD-tests.

# Envelope encryption tests using AWS KMS AEAD-implementations.
aead_aws_test() {
  local test_name="aead-aws-test"
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

KEY_TEMPLATES=(AES128_GCM AES128_CTR_HMAC_SHA256)
ENCRYPT_CLIS=($GO_AEAD_CLI $JAVA_AEAD_CLI $CC_AEAD_CLI $PY_AEAD_CLI)
DECRYPT_CLIS=($GO_AEAD_CLI $JAVA_AEAD_CLI $CC_AEAD_CLI $PY_AEAD_CLI)
# TODO(b/154273145): re-enable this
# aead_gcp_test "${ENCRYPT_CLIS[*]}" "${DECRYPT_CLIS[*]}" "${KEY_TEMPLATES[*]}"
aead_aws_test "${ENCRYPT_CLIS[*]}" "${DECRYPT_CLIS[*]}" "${KEY_TEMPLATES[*]}"
