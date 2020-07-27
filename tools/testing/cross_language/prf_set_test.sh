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
CC_PRF_SET_CLI="$ROOT_DIR/testing/cc/prf_set_cli_cc"
GO_PRF_SET_CLI="$ROOT_DIR/testing/go/prf_set_cli_go"
JAVA_PRF_SET_CLI="$ROOT_DIR/testing/prf_set_cli_java"
TEST_UTIL="$ROOT_DIR/testing/cross_language/test_util.sh"

source $TEST_UTIL || exit 1

#############################################################################
### Helpers for PRF set-tests.

# Basic tests of PRF set-implementations.
prf_set_basic_test() {
  local test_name="prf_set-basic-test"
  local clis=$1
  local output_lengths=$2
  local key_templates=$3

  echo "############ starting test $test_name for the following templates:"
  echo $key_templates
    for key_template in ${key_templates[*]}
    do
      local test_instance="${test_name}_${key_template}"

      generate_symmetric_keys "${test_instance}_PRF_set" $key_template "BINARY" 4
      generate_plaintext $test_instance

      echo "## TEST for the following output lengths:"
      echo $output_lengths
      for output_length in ${output_lengths}
      do
        local prf_files=""
        echo "## TEST for key template $key_template"
        echo $clis
        for cli in ${clis[*]}
        do
          local cli_name=$(basename $cli)
          echo "## COMPUTING PRF set using $cli_name"

          local prf_file="$TEST_TMPDIR/${test_instance}_PRF_set_${cli_name}_${output_length}_result"

          $cli $symmetric_key_file $plaintext_file ${prf_file}_tmp $output_length \
              || exit 1
          cat ${prf_file}_tmp | sort > $prf_file
          echo "## Result for ${cli_name}:"
          cat $prf_file
          assert_files_different $plaintext_file $prf_file
          prf_files="${prf_files} ${prf_file}"
          echo "## CHECKING against files:"
          echo $prf_files
          for other_file in ${prf_files}
          do
            assert_files_equal $prf_file $other_file
          done
        done
      done
    done
}

#############################################################################
##### Run the actual tests.

KEY_TEMPLATES=(HMAC_SHA256_PRF HMAC_SHA512_PRF HKDF_SHA256 AES_CMAC_PRF)
PRF_CLIS=($CC_PRF_SET_CLI $JAVA_PRF_SET_CLI $GO_PRF_SET_CLI)
OUTPUT_LENGTHS=(1 2 5 10 16 17 20 32 33 48 64 65 100 256 512 1024)
prf_set_basic_test "${PRF_CLIS[*]}" "${OUTPUT_LENGTHS[*]}" \
    "${KEY_TEMPLATES[*]}"
