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
CC_AEAD_CLI="$ROOT_DIR/tools/testing/cc/streaming_aead_cli_cc"
JAVA_AEAD_CLI="$ROOT_DIR/tools/testing/streaming_aead_cli_java"
TEST_UTIL="$ROOT_DIR/tools/testing/cross_language/test_util.sh"

source $TEST_UTIL || exit 1

#############################################################################
### Helpers for streaming AEAD-tests.

# Basic tests of streaming AEAD-implementations.
streaming_aead_basic_test() {
  local test_name="streaming-aead-basic-test"
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
      local test_file_size_mb=5
      generate_symmetric_key "${test_instance}_ENCRYPT_${encrypt_cli_name}" \
          $key_template
      generate_long_plaintext $test_instance $test_file_size_mb 1048576

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
##### Run the actual tests.
KEY_TEMPLATES=(AES128_GCM_HKDF_4KB AES256_GCM_HKDF_4KB AES128_CTR_HMAC_SHA256_4KB AES256_CTR_HMAC_SHA256_4KB)
ENCRYPT_CLIS=($CC_AEAD_CLI $JAVA_AEAD_CLI)
DECRYPT_CLIS=($CC_AEAD_CLI $JAVA_AEAD_CLI)
streaming_aead_basic_test "${ENCRYPT_CLIS[*]}" "${DECRYPT_CLIS[*]}" "${KEY_TEMPLATES[*]}"
