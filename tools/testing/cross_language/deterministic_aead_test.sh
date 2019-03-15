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
CC_DAEAD_CLI="$ROOT_DIR/tools/testing/cc/deterministic_aead_cli_cc"
JAVA_DAEAD_CLI="$ROOT_DIR/tools/testing/deterministic_aead_cli_java"
GO_DAEAD_CLI="$ROOT_DIR/tools/testing/go/deterministic_aead_cli_go"
TEST_UTIL="$ROOT_DIR/tools/testing/cross_language/test_util.sh"

KEY_TEMPLATES=(AES256_SIV)

source $TEST_UTIL || exit 1

#############################################################################
### Helpers for DeterministicAead-tests.

# Basic tests of DeterministicAead-implementations.
deterministic_aead_basic_test() {
  local test_name="$1-aead-basic-test"
  local encrypt_cli="$2"
  local decrypt_cli="$3"
  local key_templates=$4

  echo "############ starting test $test_name for the following templates:"
  echo $key_templates
  for key_template in ${key_templates[*]}
  do
    local test_instance="${test_name}_${key_template}"
    generate_symmetric_key $test_instance $key_template
    generate_plaintext $test_instance

    local encrypted_file="$TEST_TMPDIR/${test_instance}_encrypted.bin"
    local decrypted_file="$TEST_TMPDIR/${test_instance}_decrypted.bin"
    local associated_data_file="$TEST_TMPDIR/${test_instance}_aad.bin"
    echo "some associated data for $test_instance" > $associated_data_file
    $encrypt_cli $symmetric_key_file "encryptdeterministically" $plaintext_file\
        $associated_data_file $encrypted_file || exit 1
    assert_files_different $plaintext_file $encrypted_file
    $decrypt_cli $symmetric_key_file "decryptdeterministically" $encrypted_file\
        $associated_data_file $decrypted_file || exit 1
    assert_files_equal $plaintext_file $decrypted_file
  done
}

#############################################################################
##### Run the actual tests.
deterministic_aead_basic_test "CC-CC"\
    $CC_DAEAD_CLI   $CC_DAEAD_CLI   "${KEY_TEMPLATES[*]}"
deterministic_aead_basic_test "CC-JAVA"\
    $CC_DAEAD_CLI   $JAVA_DAEAD_CLI "${KEY_TEMPLATES[*]}"
deterministic_aead_basic_test "JAVA-CC"\
    $JAVA_DAEAD_CLI $CC_DAEAD_CLI   "${KEY_TEMPLATES[*]}"
deterministic_aead_basic_test "JAVA-JAVA"\
    $JAVA_DAEAD_CLI $JAVA_DAEAD_CLI "${KEY_TEMPLATES[*]}"
deterministic_aead_basic_test "GO-GO"\
    $GO_DAEAD_CLI $GO_DAEAD_CLI "${KEY_TEMPLATES[*]}"
deterministic_aead_basic_test "GO-JAVA"\
    $GO_DAEAD_CLI $JAVA_DAEAD_CLI "${KEY_TEMPLATES[*]}"
deterministic_aead_basic_test "JAVA-GO"\
    $JAVA_DAEAD_CLI $GO_DAEAD_CLI "${KEY_TEMPLATES[*]}"
deterministic_aead_basic_test "CC-GO"\
    $CC_DAEAD_CLI $GO_DAEAD_CLI "${KEY_TEMPLATES[*]}"
deterministic_aead_basic_test "GO-CC"\
    $GO_DAEAD_CLI $CC_DAEAD_CLI "${KEY_TEMPLATES[*]}"


