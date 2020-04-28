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


ROOT_DIR="$TEST_SRCDIR/tools"
CC_MAC_CLI="$ROOT_DIR/testing/cc/mac_cli_cc"
GO_MAC_CLI="$ROOT_DIR/testing/go/mac_cli_go"
JAVA_MAC_CLI="$ROOT_DIR/testing/mac_cli_java"
PY_MAC_CLI="$ROOT_DIR/testing/python/mac_cli_python"
TEST_UTIL="$ROOT_DIR/testing/cross_language/test_util.sh"

source $TEST_UTIL || exit 1

#############################################################################
### Helpers for MAC-tests.

# Basic tests of MAC-implementations.
mac_basic_test() {
  local test_name="mac-basic-test"
  local compute_mac_clis=$1
  local verify_mac_clis=$2
  local key_templates=$3

  echo "############ starting test $test_name for the following templates:"
  echo $key_templates
    for key_template in ${key_templates[*]}
    do
      echo "## TEST for key template $key_template"
      echo $compute_mac_clis
      for compute_mac_cli in ${compute_mac_clis[*]}
      do
        local compute_mac_cli_name=$(basename $compute_mac_cli)
        echo "## COMPUTING MAC using $compute_mac_cli_name"
        local test_instance="${test_name}_${key_template}"

        generate_symmetric_key "${test_instance}_MAC_${compute_mac_cli_name}" $key_template
        generate_plaintext $test_instance

        local mac_file="$TEST_TMPDIR/${test_instance}_MAC_${compute_mac_cli_name}_mac.bin"

        $compute_mac_cli $symmetric_key_file "compute" $plaintext_file\
            $mac_file || exit 1
        assert_files_different $plaintext_file $mac_file

        for verify_mac_cli in ${verify_mac_clis[*]}
        do
          local verify_mac_cli_name=$(basename $verify_mac_cli)
          local result_file="$TEST_TMPDIR/${test_instance}_MAC_${compute_mac_cli_name}_VERIFY_${verify_mac_cli_name}_verification.txt"

          echo "## VERIFYING using $verify_mac_cli_name"

          $verify_mac_cli $symmetric_key_file "verify" $plaintext_file\
              $mac_file $result_file || exit 1
          assert_file_equals "valid" $result_file

        done
      done
    done
}

#############################################################################
##### Run the actual tests.

KEY_TEMPLATES=(HMAC_SHA256_128BITTAG HMAC_SHA256_256BITTAG HMAC_SHA512_256BITTAG HMAC_SHA512_512BITTAG AES_CMAC)
MAC_CLIS=($CC_MAC_CLI $JAVA_MAC_CLI $GO_MAC_CLI $PY_MAC_CLI)
VERIFY_CLIS=($CC_MAC_CLI $JAVA_MAC_CLI $GO_MAC_CLI $PY_MAC_CLI)
mac_basic_test "${MAC_CLIS[*]}" "${VERIFY_CLIS[*]}" \
    "${KEY_TEMPLATES[*]}"

