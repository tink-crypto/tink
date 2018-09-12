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

#!/bin/bash

ROOT_DIR="$TEST_SRCDIR/tink"
CC_ENCRYPT_CLI="$ROOT_DIR/tools/testing/cc/hybrid_encrypt_cli_cc"
CC_DECRYPT_CLI="$ROOT_DIR/tools/testing/cc/hybrid_decrypt_cli_cc"
JAVA_ENCRYPT_CLI="$ROOT_DIR/tools/testing/hybrid_encrypt_cli_java"
JAVA_DECRYPT_CLI="$ROOT_DIR/tools/testing/hybrid_decrypt_cli_java"
TEST_UTIL="$ROOT_DIR/tools/testing/cross_language/test_util.sh"

KEY_TEMPLATES=(ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256 ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM)

source $TEST_UTIL || exit 1


#############################################################################
### Helpers for hybrid-tests.

# Basic tests of HybridEncrypt and HybridDecrypt.
hybrid_basic_test() {
  local test_name="$1-hybrid-basic-test"
  local encrypt_cli="$2"
  local decrypt_cli="$3"
  local key_templates=$4

  echo "############ starting test $test_name for the following templates:"
  echo $key_templates
  for key_template in ${key_templates[*]}
  do
    local test_instance="${test_name}_${key_template}"
    generate_asymmetric_keys $test_instance $key_template
    generate_plaintext $test_instance

    local encrypted_file="$TEST_TMPDIR/${test_instance}_encrypted.bin"
    local decrypted_file="$TEST_TMPDIR/${test_instance}_decrypted.bin"
    local context_info_file="$TEST_TMPDIR/${test_instance}_context_info.bin"
    echo "some context info for $test_instance" > $context_info_file
    $encrypt_cli $pub_key_file $plaintext_file $context_info_file \
        $encrypted_file || exit 1
    assert_files_different $plaintext_file $encrypted_file
    $decrypt_cli $priv_key_file $encrypted_file $context_info_file \
        $decrypted_file || exit 1
    assert_files_equal $plaintext_file $decrypted_file
  done
}

#############################################################################
##### Run the actual tests.
hybrid_basic_test "CC-CC"     $CC_ENCRYPT_CLI   $CC_DECRYPT_CLI   "${KEY_TEMPLATES[*]}"
hybrid_basic_test "CC-JAVA"   $CC_ENCRYPT_CLI   $JAVA_DECRYPT_CLI "${KEY_TEMPLATES[*]}"
hybrid_basic_test "JAVA-CC"   $JAVA_ENCRYPT_CLI $CC_DECRYPT_CLI   "${KEY_TEMPLATES[*]}"
hybrid_basic_test "JAVA-JAVA" $JAVA_ENCRYPT_CLI $JAVA_DECRYPT_CLI "${KEY_TEMPLATES[*]}"


