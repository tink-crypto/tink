#!/bin/bash
# Copyright 2018 Google LLC
#
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
TINKEY_CLI="$ROOT_DIR/tinkey/tinkey"
ENVELOPE_CLI="$ROOT_DIR/testing/go/generate_envelope_keyset"
#############################################################################
##### Helper functions.

# Generates private and public keys according to $key_template,
# which should be supported by Tinkey.
# If $output_prefix is specified, the generated keyset will use it
# instead of default value "TINK".
# Stores the keys in files $priv_key_file and $pub_key_file, respectively.
generate_asymmetric_keys() {
  local key_name="$1"
  local key_template="$2"
  local output_prefix="$3"
  if [ "$output_prefix" == "" ]; then
    output_prefix="TINK"
  fi

  local json_priv_key_file="$TEST_TMPDIR/${key_name}_private_key.json"
  priv_key_file="$TEST_TMPDIR/${key_name}_private_key.bin"
  pub_key_file="$TEST_TMPDIR/${key_name}_public_key.bin"
  echo "--- Using template $key_template to generate keysets"\
      "to files $priv_key_file and $pub_key_file ..."

  $TINKEY_CLI create-keyset --key-template  $key_template --out-format JSON\
    | sed -e "s/\"TINK\"/\"$output_prefix\"/" > $json_priv_key_file  || exit 1
  $TINKEY_CLI convert-keyset --in-format JSON --in $json_priv_key_file\
    --out-format BINARY --out $priv_key_file  || exit 1
  $TINKEY_CLI create-public-keyset --in-format BINARY --in $priv_key_file\
      --out-format BINARY --out $pub_key_file  || exit 1
  echo "Done generating keysets."
}

# Generates a symmetric key according to $key_template,
# which should be supported by Tinkey.
# Stores the key in file $symmetric_key_file.
generate_symmetric_key() {
  local key_name="$1"
  local key_template="$2"
  local output_format="$3"
  if [ "$output_format" == "" ]; then
    output_format="BINARY"
  fi

  symmetric_key_file="$TEST_TMPDIR/${key_name}_symmetric_key.bin"
  echo "--- Using template $key_template to generate keyset"\
      "to file $symmetric_key_file ..."

  $TINKEY_CLI create-keyset --key-template $key_template\
      --out-format $output_format --out $symmetric_key_file  || exit 1
  echo "Done generating a symmetric keyset."
}

# Generates an AWS Envelope Encryption using $key_template,
# which should be supported by Tinkey.
# Stores the key in file $aws_keyset_file.
generate_aws_keyset() {
  local key_name="$1"
  local key_template="$2"
  local output_format="$3"
  if [ "$output_format" == "" ]; then
    output_format="BINARY"
  fi
  aws_keyset_file="$TEST_TMPDIR/${key_name}_aws_keyset.bin"
  echo "--- Using AWS KMS and template $key_template to generate keyset"\
       "to file $aws_keyset_file ..."

  $ENVELOPE_CLI $aws_keyset_file "AWS" $key_template || exit 1

  echo "Done generating an AWS KMS generated keyset."
}

# Generates an GCP Envelope Encryption using $key_template,
# which should be supported by Tinkey.
# Stores the key in file $gcp_keyset_file.
generate_gcp_keyset() {
  local key_name="$1"
  local key_template="$2"
  local output_format="$3"

  if [ "$output_format" == "" ]; then
    output_format="BINARY"
  fi
  gcp_keyset_file="$TEST_TMPDIR/${key_name}_gcp_keyset.bin"
  echo "--- Using GCP KMS and template $key_template to generate keyset"\
      "to file $gcp_keyset_file ..."
  $ENVELOPE_CLI $gcp_keyset_file "GCP" $key_template || exit 1

  echo "Done generating an GCP KMS generated keyset."

}

# Generates some example plaintext data, and stores it in $plaintext_file.
generate_plaintext() {
  local plaintext_name="$1"

  plaintext_file="$TEST_TMPDIR/${plaintext_name}_plaintext.bin"
  echo "This is some plaintext message to be encrypted and/or signed" \
       " named $plaintext_name just like that." > $plaintext_file
}

# Checks that two files are equal.
assert_files_equal() {
  local expected_file="$1"
  local given_file="$2"
  echo "*** Checking that 2 files are equal:"
  echo "    file #1: $expected_file"
  echo "    file #2: $given_file"
  diff $expected_file $given_file
  if [ $? -ne 0 ]; then
    echo "--- Failure: the files are different."
    exit 1
  fi
  echo "+++ Success: the files are equal."
}

# Checks that the given file has the expected content.
assert_file_equals() {
  local expected_content="$1"
  local given_file="$2"
  echo "*** Checking that given file: $given_file"
  echo "    has content equal to \"$expected_content\""
  local file_content=`cat $given_file`
  if [ "$expected_content" != "$file_content" ]; then
    echo "--- Failure. expected content: \"$expected_content\","\
        " actual content: \"$file_content\""
    exit 1
  fi
  echo "+++ Success: the file has expected content: \"$expected_content\"."
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

# Checks that a given file contains specified substrings.
assert_file_contains() {
  local file_to_test="$1"
  echo "*** Checking that file $file_to_test contains substrings:"
  cat $file_to_test
  # Shift the first argument and iterate through the remaining ones.
  shift
  for s do
  echo "... checking for string [$s]"
  if grep -q "$s" "$file_to_test"; then
    echo "   found"
  else
    echo "--- Failure: file does not contain string [$s]"
    exit 1
  fi
  done
  echo "+++ Success: file contains all expected substrings."
}
