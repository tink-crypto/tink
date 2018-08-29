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
CC_MAC_CLI="$ROOT_DIR/tools/testing/cc/mac_cli_cc"
JAVA_MAC_CLI="$ROOT_DIR/tools/testing/mac_cli_java"
TEST_UTIL="$ROOT_DIR/tools/testing/cross_language/test_util.sh"

KEY_TEMPLATES=(HMAC_SHA256_128BITTAG HMAC_SHA256_256BITTAG)

source $TEST_UTIL || exit 1

#############################################################################
### Helpers for MAC-tests.

# Basic tests of MAC-implementations.
mac_basic_test() {
  local test_name="$1-mac-basic-test-$5"
  local compute_mac_cli="$2"
  local verify_mac_cli="$3"
  local key_templates=$4
  local output_prefix="$5"

  echo "############ starting test $test_name for the following templates:"
  echo $key_templates
  for key_template in ${key_templates[*]}
  do
    local test_instance="${test_name}_${key_template}"
    generate_symmetric_key $test_instance $key_template
    generate_plaintext $test_instance

    local mac_file="$TEST_TMPDIR/${test_instance}_mac.bin"
    local result_file="$TEST_TMPDIR/${test_instance}_result.txt"
    $compute_mac_cli $symmetric_key_file "compute" $plaintext_file\
        $mac_file || exit 1
    assert_files_different $plaintext_file $mac_file
    $verify_mac_cli $symmetric_key_file "verify" $plaintext_file\
        $mac_file $result_file || exit 1
    assert_file_equals "valid" $result_file
  done
}

#############################################################################
##### Run the actual tests.

### Tests with OutputPrefixType=="TINK"
mac_basic_test "CC-CC"     $CC_MAC_CLI   $CC_MAC_CLI   \
  "${KEY_TEMPLATES[*]}" "TINK"
mac_basic_test "CC-JAVA"   $CC_MAC_CLI   $JAVA_MAC_CLI \
  "${KEY_TEMPLATES[*]}" "TINK"
mac_basic_test "JAVA-CC"   $JAVA_MAC_CLI $CC_MAC_CLI   \
  "${KEY_TEMPLATES[*]}" "TINK"
mac_basic_test "JAVA-JAVA" $JAVA_MAC_CLI $JAVA_MAC_CLI \
  "${KEY_TEMPLATES[*]}" "TINK"

### Tests with OutputPrefixType=="LEGACY"
mac_basic_test "CC-CC"     $CC_MAC_CLI   $CC_MAC_CLI   \
  "${KEY_TEMPLATES[*]}" "LEGACY"
mac_basic_test "CC-JAVA"   $CC_MAC_CLI   $JAVA_MAC_CLI \
  "${KEY_TEMPLATES[*]}" "LEGACY"
mac_basic_test "JAVA-CC"   $JAVA_MAC_CLI $CC_MAC_CLI   \
  "${KEY_TEMPLATES[*]}" "LEGACY"
mac_basic_test "JAVA-JAVA" $JAVA_MAC_CLI $JAVA_MAC_CLI \
  "${KEY_TEMPLATES[*]}" "LEGACY"
