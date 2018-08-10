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

ROOT_DIR="$TEST_SRCDIR/__main__"
TINKEY_CLI="$ROOT_DIR/tools/tinkey/tinkey"

#############################################################################
##### Helper functions.

# Generates private and public keys according to $key_template,
# which should be present in a subdirectory $templates_subdir.
# Stores the keys in files $priv_key_file and $pub_key_file, respectively.
generate_asymmetric_keys() {
  local templates_subdir="$1"
  local key_name="$2"
  local key_template="$3"

  priv_key_file="$TEST_TMPDIR/${key_name}_private_key.bin"
  pub_key_file="$TEST_TMPDIR/${key_name}_public_key.bin"
  echo "--- Using template $key_template to generate keysets"\
      "to files $priv_key_file and $pub_key_file ..."

  $TINKEY_CLI create-keyset --key-template  $key_template\
      --out-format BINARY --out $priv_key_file  || exit 1
  $TINKEY_CLI create-public-keyset --in-format BINARY --in $priv_key_file\
      --out-format BINARY --out $pub_key_file  || exit 1
  echo "Done generating keysets."
}

# Generates a symmetric key according to $key_template,
# which should be present in a subdirectory $templates_subdir.
# Stores the key in file $symmetric_key_file.
generate_symmetric_key() {
  local templates_subdir="$1"
  local key_name="$2"
  local key_template="$3"
  local output_format="$4"
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

# Generates some example plaintext data, and stores it in $plaintext_file.
generate_plaintext() {
  local plaintext_name="$1"

  plaintext_file="$TEST_TMPDIR/${plaintext_name}_plaintext.bin"
  echo "This is some plaintext message to be encrypted"\
      " named $plaintext_name just like that." > $plaintext_file
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
