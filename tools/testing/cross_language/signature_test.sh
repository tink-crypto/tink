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
CC_SIGN_CLI="$ROOT_DIR/tools/testing/cc/public_key_sign_cli_cc"
CC_VERIFY_CLI="$ROOT_DIR/tools/testing/cc/public_key_verify_cli_cc"
JAVA_SIGN_CLI="$ROOT_DIR/tools/testing/public_key_sign_cli_java"
JAVA_VERIFY_CLI="$ROOT_DIR/tools/testing/public_key_verify_cli_java"
GO_SIGN_CLI="$ROOT_DIR/tools/testing/go/public_key_sign_cli_go"
GO_VERIFY_CLI="$ROOT_DIR/tools/testing/go/public_key_verify_cli_go"
TEST_UTIL="$ROOT_DIR/tools/testing/cross_language/test_util.sh"

source $TEST_UTIL || exit 1


#############################################################################
### Helpers for signature-tests.

# Basic tests of PublicKeySign and PublicKeyVerify implementations.
signature_basic_test() {
  local test_name="signature-basic-test"
  local sign_clis=$1
  local verify_clis=$2
  local key_templates=$3
  local output_prefixes=$4

  echo "############ starting test $test_name for the following templates:"
  echo $key_templates
  for output_prefix in ${output_prefixes[*]}
  do
    for key_template in ${key_templates[*]}
    do
      echo "## TEST for key template $key_template, output prefix $output_prefix"
      for sign_cli in ${sign_clis[*]}
      do
        local sign_cli_name=`get_file_name $sign_cli`
        echo "## SIGNING using $sign_cli_name"
        local test_instance="${test_name}_${key_template}"

        generate_asymmetric_keys "${test_instance}_SIGN_${output_prefix}_${sign_cli_name}" \
            $key_template $output_prefix
        generate_plaintext $test_instance

        local signature_file="$TEST_TMPDIR/${test_instance}_SIGN_${sign_cli_name}_signature.bin"
        $sign_cli $priv_key_file $plaintext_file $signature_file || exit 1
        assert_files_different $plaintext_file $signature_file

        for verify_cli in ${verify_clis[*]}
        do
          local verify_cli_name=`get_file_name "$verify_cli"`
          local verification_file="$TEST_TMPDIR/${test_instance}_SIGN_${output_prefix}_${sign_cli_name}_VERIFY_${verify_cli_name}_verification.bin"
          echo "## VERIFYING using $verify_cli_name"
          $verify_cli $pub_key_file $signature_file $plaintext_file\
              $verification_file || exit 1
          assert_file_equals "valid" $verification_file
        done
      done
    done
  done
}

#############################################################################
##### Run the actual tests.

# Common tests for Java, C++ and Go
KEY_TEMPLATES=(ECDSA_P256 ECDSA_P384 ECDSA_P521 ECDSA_P256_IEEE_P1363 ECDSA_P384_IEEE_P1363 ECDSA_P521_IEEE_P1363 ED25519)
OUTPUT_PREFIXES=(TINK LEGACY)
SIGN_CLIS=($CC_SIGN_CLI $JAVA_SIGN_CLI $GO_SIGN_CLI)
VERIFY_CLIS=($CC_VERIFY_CLI $JAVA_VERIFY_CLI $GO_VERIFY_CLI)
signature_basic_test "${SIGN_CLIS[*]}" "${VERIFY_CLIS[*]}" \
    "${KEY_TEMPLATES[*]}" "${OUTPUT_PREFIXES[*]}"

# These tests work only in Java and C++
KEY_TEMPLATES=(RSA_SSA_PKCS1_3072_SHA256_F4 RSA_SSA_PKCS1_4096_SHA512_F4 RSA_SSA_PSS_3072_SHA256_SHA256_32_F4 RSA_SSA_PSS_4096_SHA512_SHA512_64_F4)
OUTPUT_PREFIXES=(TINK LEGACY)
SIGN_CLIS=($CC_SIGN_CLI $JAVA_SIGN_CLI)
VERIFY_CLIS=($CC_VERIFY_CLI $JAVA_VERIFY_CLI)
signature_basic_test "${SIGN_CLIS[*]}" "${VERIFY_CLIS[*]}" \
    "${KEY_TEMPLATES[*]}" "${OUTPUT_PREFIXES[*]}"
