#!/bin/bash

ROOT_DIR="$TEST_SRCDIR/__main__"
CC_SIGN_CLI="$ROOT_DIR/tools/testing/cc/public_key_sign_cli_cc"
CC_VERIFY_CLI="$ROOT_DIR/tools/testing/cc/public_key_verify_cli_cc"
JAVA_SIGN_CLI="$ROOT_DIR/tools/testing/public_key_sign_cli_java"
JAVA_VERIFY_CLI="$ROOT_DIR/tools/testing/public_key_verify_cli_java"
TEST_UTIL="$ROOT_DIR/tools/testing/cross_language/test_util.sh"

KEY_TEMPLATES=(ECDSA_P256 ECDSA_P384 ECDSA_P521)

source $TEST_UTIL || exit 1


#############################################################################
### Helpers for signature-tests.

# Basic tests of PublicKeySign and PublicKeyVerify.
signature_basic_test() {
  local test_name="$1-signature-basic-test"
  local sign_cli="$2"
  local verify_cli="$3"
  local key_templates=$4

  echo "############ starting test $test_name for the following templates:"
  echo $key_templates
  for key_template in ${key_templates[*]}
  do
    local test_instance="${test_name}_${key_template}"
    generate_asymmetric_keys "signature" $test_instance $key_template
    generate_plaintext $test_instance

    local signature_file="$TEST_TMPDIR/${test_instance}_signature.bin"
    local verification_file="$TEST_TMPDIR/${test_instance}_verification.bin"
    $sign_cli $priv_key_file $plaintext_file $signature_file || exit 1
    assert_files_different $plaintext_file $signature_file
    $verify_cli $pub_key_file $signature_file $plaintext_file\
        $verification_file || exit 1
    assert_file_equals "valid" $verification_file
  done
}

#############################################################################
##### Run the actual tests.
signature_basic_test "CC-CC"     $CC_SIGN_CLI   $CC_VERIFY_CLI   "${KEY_TEMPLATES[*]}"
signature_basic_test "CC-JAVA"   $CC_SIGN_CLI   $JAVA_VERIFY_CLI "${KEY_TEMPLATES[*]}"
signature_basic_test "JAVA-CC"   $JAVA_SIGN_CLI $CC_VERIFY_CLI   "${KEY_TEMPLATES[*]}"
signature_basic_test "JAVA-JAVA" $JAVA_SIGN_CLI $JAVA_VERIFY_CLI "${KEY_TEMPLATES[*]}"


