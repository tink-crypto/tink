#!/bin/bash

ROOT_DIR="$TEST_SRCDIR/__main__"
TINKEY_CLI="$ROOT_DIR/tools/tinkey/tinkey"
CC_ENCRYPT_CLI="$ROOT_DIR/tools/testing/cc/hybrid_encrypt_cli_cc"
CC_DECRYPT_CLI="$ROOT_DIR/tools/testing/cc/hybrid_decrypt_cli_cc"
JAVA_ENCRYPT_CLI="$ROOT_DIR/tools/testing/hybrid_encrypt_cli_java"
JAVA_DECRYPT_CLI="$ROOT_DIR/tools/testing/hybrid_decrypt_cli_java"

KEY_TEMPLATES=(ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256.ascii ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM.ascii)

#############################################################################
##### Helper functions.

# Generates private and public keys according to $KEY_TEMPLATE.
# Stores the keys in files $priv_key_file and $pub_key_file, respectively.
generate_keys() {
  local key_name="$1"
  local key_template="$2"

  priv_key_file="$TEST_TMPDIR/${key_name}_${key_template}_private_key.bin"
  pub_key_file="$TEST_TMPDIR/${key_name}_${key_template}_public_key.bin"
  echo "--- Using template $key_template to generate keysets" \
      "to files $priv_key_file and $pub_key_file ..."

  $TINKEY_CLI create-keyset --key-template $ROOT_DIR/examples/keytemplates/hybrid/$key_template \
      --out-format BINARY --out $priv_key_file  || exit 1
  $TINKEY_CLI create-public-keyset --in-format BINARY --in $priv_key_file \
      --out-format BINARY --out $pub_key_file  || exit 1
  echo "Done generating keysets."
}

# Generates some example plaintext data, and stores it in $plaintext_file.
generate_plaintext() {
  local plaintext_name="$1"

  plaintext_file="$TEST_TMPDIR/${plaintext_name}_plaintext.bin"
  echo "This is some plaintext message to be encrypted"\
    "named $plaintext_name just like that." > $plaintext_file
}

# Checks that two files are equal.
assert_files_equal() {
  local expected_file="$1"
  local given_file="$2"
  echo "*** Checking that 2 files are equal:"
  echo "    file #1: $expected_file"
  echo "    file #2: $given_file"
  diff -q $expected_file $given_file
  if [ $? -ne 0 ]; then
    echo "--- Failure: the files are different."
    exit 1
  fi
  echo "+++ Success: the files are equal."
}

# Checks that two files are different.
assert_files_different() {
  local expected_file="$1"
  local given_file="$2"
  echo "*** Checking that 2 files are different:"
  echo "    file #1: $expected_file"
  echo "    file #2: $given_file"
  diff -q $expected_file $given_file
  if [ $? -eq 0 ]; then
    echo "--- Failure: the files are equal."
    exit 1
  fi
  echo "+++ Success: the files are different."
}

#############################################################################
##### Functions that do the actual testing.

# Encrypt and Decrypt with C++.
cc_cc_basic_test() {
  local test_name="cc_cc_basic_test"
  echo "############ starting test $test_name ..."
  for key_template in ${KEY_TEMPLATES[*]}
  do
    generate_keys $test_name $key_template
    generate_plaintext $test_name

    local encrypted_file="$TEST_TMPDIR/${test_name}_encrypted.bin"
    local decrypted_file="$TEST_TMPDIR/${test_name}_decrypted.bin"
    local context_info="some context info for $test_name"
    $CC_ENCRYPT_CLI $pub_key_file $plaintext_file "$context_info" \
        $encrypted_file || exit 1
    assert_files_different $plaintext_file $encrypted_file
    $CC_DECRYPT_CLI $priv_key_file $encrypted_file "$context_info" \
        $decrypted_file || exit 1
    assert_files_equal $plaintext_file $decrypted_file
  done
}

# Encrypt with C++, Decrypt with Java.
cc_java_basic_test() {
  local test_name="cc_java_basic_test"
  echo "############ starting test $test_name ..."
  for key_template in ${KEY_TEMPLATES[*]}
  do
    generate_keys $test_name $key_template
    generate_plaintext $test_name

    local encrypted_file="$TEST_TMPDIR/${test_name}_encrypted.bin"
    local decrypted_file="$TEST_TMPDIR/${test_name}_decrypted.bin"
    local context_info="some context info for $test_name"
    $CC_ENCRYPT_CLI $pub_key_file $plaintext_file "$context_info" \
        $encrypted_file || exit 1
    assert_files_different $plaintext_file $encrypted_file
    $JAVA_DECRYPT_CLI $priv_key_file $encrypted_file "$context_info" \
        $decrypted_file || exit 1
    assert_files_equal $plaintext_file $decrypted_file
  done
}

# Encrypt with Java, Decrypt with C++.
java_cc_basic_test() {
  local test_name="java_cc_basic_test"
  echo "############ starting test $test_name ..."
  for key_template in ${KEY_TEMPLATES[*]}
  do
    generate_keys $test_name $key_template
    generate_plaintext $test_name

    local encrypted_file="$TEST_TMPDIR/${test_name}_encrypted.bin"
    local decrypted_file="$TEST_TMPDIR/${test_name}_decrypted.bin"
    local context_info="some context info for $test_name"
    $JAVA_ENCRYPT_CLI $pub_key_file $plaintext_file "$context_info" \
        $encrypted_file || exit 1
    assert_files_different $plaintext_file $encrypted_file
    $CC_DECRYPT_CLI $priv_key_file $encrypted_file "$context_info" \
        $decrypted_file || exit 1
    assert_files_equal $plaintext_file $decrypted_file
  done
}

# Encrypt and Decrypt with Java.
java_java_basic_test() {
  local test_name="java_java_basic_test"
  echo "############ starting test $test_name ..."
  for key_template in ${KEY_TEMPLATES[*]}
  do
    generate_keys $test_name $key_template
    generate_plaintext $test_name

    local encrypted_file="$TEST_TMPDIR/${test_name}_encrypted.bin"
    local decrypted_file="$TEST_TMPDIR/${test_name}_decrypted.bin"
    local context_info="some context info for $test_name"
    $JAVA_ENCRYPT_CLI $pub_key_file $plaintext_file "$context_info" \
        $encrypted_file || exit 1
    assert_files_different $plaintext_file $encrypted_file
    $JAVA_DECRYPT_CLI $priv_key_file $encrypted_file "$context_info" \
        $decrypted_file || exit 1
    assert_files_equal $plaintext_file $decrypted_file
  done
}

#############################################################################
##### The main function.
main() {
  cc_cc_basic_test
  cc_java_basic_test
  java_cc_basic_test
  java_java_basic_test
}

#############################################################################
##### Run the tests.
main


