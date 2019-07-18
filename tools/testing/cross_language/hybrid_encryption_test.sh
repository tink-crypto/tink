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
CC_ENCRYPT_CLI="$ROOT_DIR/tools/testing/cc/hybrid_encrypt_cli_cc"
CC_DECRYPT_CLI="$ROOT_DIR/tools/testing/cc/hybrid_decrypt_cli_cc"
JAVA_ENCRYPT_CLI="$ROOT_DIR/tools/testing/hybrid_encrypt_cli_java"
JAVA_DECRYPT_CLI="$ROOT_DIR/tools/testing/hybrid_decrypt_cli_java"
TEST_UTIL="$ROOT_DIR/tools/testing/cross_language/test_util.sh"
GO_ENCRYPT_CLI="$ROOT_DIR/tools/testing/go/hybrid_encrypt_cli_go"
GO_DECRYPT_CLI="$ROOT_DIR/tools/testing/go/hybrid_decrypt_cli_go"

source $TEST_UTIL || exit 1

#############################################################################
### Helpers for hybrid-tests.

# Basic tests of HybridEncrypt and HybridDecrypt implementations.
hybrid_basic_test() {
  local test_name="hybrid-basic-test"
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
      generate_asymmetric_keys "${test_instance}_ENCRYPT_${encrypt_cli_name}" \
          $key_template
      generate_plaintext $test_instance

      local encrypted_file="$TEST_TMPDIR/${test_instance}_ENCRYPT_${encrypt_cli_name}_encrypted.bin"
      local context_info_file="$TEST_TMPDIR/${test_instance}_ENCRYPT_${encrypt_cli_name}_context_info.bin"
      echo "some context info for $test_instance using $encrypt_cli_name" \
          "for encryption" > $context_info_file

      $encrypt_cli $pub_key_file $plaintext_file $context_info_file \
          $encrypted_file || exit 1
      assert_files_different $plaintext_file $encrypted_file
      for decrypt_cli in ${decrypt_clis[*]}
      do
        local decrypt_cli_name=$(basename "$decrypt_cli")
        local decrypted_file="$TEST_TMPDIR/${test_instance}_ENCRYPT_${encrypt_cli_name}_DECRYPT_${decrypt_cli_name}_decrypted.bin"
        echo "## DECRYPTING using $decrypt_cli_name"
        $decrypt_cli $priv_key_file $encrypted_file $context_info_file \
            $decrypted_file || exit 1
        assert_files_equal $plaintext_file $decrypted_file
      done
    done
  done
}


#############################################################################
##### Run the actual tests.

KEY_TEMPLATES=(ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256 ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM)
ENCRYPT_CLIS=($CC_ENCRYPT_CLI $JAVA_ENCRYPT_CLI $GO_ENCRYPT_CLI)
DECRYPT_CLIS=($CC_DECRYPT_CLI $JAVA_DECRYPT_CLI $GO_DECRYPT_CLI)
hybrid_basic_test "${ENCRYPT_CLIS[*]}" "${DECRYPT_CLIS[*]}" \
    "${KEY_TEMPLATES[*]}"
