#!/bin/bash
# Copyright 2020 Google LLC
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


#############################################################################
#### Tests for hybrid_encrypt_cli binary.

HYBRID_CLI="$1"

PRIVATE_KEYSET_FILE="$TEST_TMPDIR/private_keyset.bin"
PUBLIC_KEYSET_FILE="$TEST_TMPDIR/public_keyset.bin"
MESSAGE_FILE="$TEST_TMPDIR/message.txt"
CONTEXT_INFO_FILE="$TEST_TMPDIR/context_info.txt"
ENCRYPTED_MESSAGE_FILE="$TEST_TMPDIR/encrypted_message.bin"
DECRYPTED_MESSAGE_FILE="$TEST_TMPDIR/decrypted_message.txt"
RESULT_FILE="$TEST_TMPDIR/result.txt"

OTHER_PRIVATE_KEYSET_FILE="$TEST_TMPDIR/other_private_keyset.bin"
OTHER_PUBLIC_KEYSET_FILE="$TEST_TMPDIR/other_public_keyset.bin"
OTHER_MESSAGE_FILE="$TEST_TMPDIR/other_message.txt"

echo "This is a message." > $MESSAGE_FILE
echo "This is a different message." > $OTHER_MESSAGE_FILE
echo "context" > $CONTEXT_INFO_FILE
echo "different context" > $OTHER_CONTEXT_INFO_FILE

#############################################################################
#### Helper function that checks if values are equal.

assert_equal() {
  if [ "$1" == "$2" ]; then
    echo "+++ Success: values are equal."
  else
    echo "--- Failure: values are different. Expected: [$1], actual: [$2]."
    exit 1
  fi
}

#############################################################################
#### All good, everything should work.
test_name="all_good"
echo "+++ Starting test $test_name..."

#### Generate a private key and get a public key.
$HYBRID_CLI gen-private-key $PRIVATE_KEYSET_FILE || exit 1
$HYBRID_CLI get-public-key $PRIVATE_KEYSET_FILE $PUBLIC_KEYSET_FILE || exit 1

#### Encrypt the message.
$HYBRID_CLI encrypt $PUBLIC_KEYSET_FILE $MESSAGE_FILE $CONTEXT_INFO_FILE $ENCRYPTED_MESSAGE_FILE || exit 1

#### Decrypt the encrypted message.
$HYBRID_CLI decrypt $PRIVATE_KEYSET_FILE $ENCRYPTED_MESSAGE_FILE $CONTEXT_INFO_FILE $DECRYPTED_MESSAGE_FILE || exit 1

#### Check that the decrypted message is same as original message.
DECRYPTED_MESSAGE=$(<$DECRYPTED_MESSAGE_FILE)
ORIGINAL_MESSAGE=$(<$MESSAGE_FILE)
assert_equal "$ORIGINAL_MESSAGE" "$DECRYPTED_MESSAGE"

#############################################################################
#### Bad private key when getting the public key.
test_name="get_public_key_with_bad_private_key"
echo "+++ Starting test $test_name..."

echo "abcd" >> $PRIVATE_KEYSET_FILE
$HYBRID_CLI get-public-key $PRIVATE_KEYSET_FILE $PUBLIC_KEYSET_FILE

EXIT_VALUE="$?"
assert_equal 1 "$EXIT_VALUE"

#############################################################################
#### Decrypting a bad encrypted file.
test_name="decrypt_a_bad_file"
echo "+++ Starting test $test_name..."

$HYBRID_CLI gen-private-key $PRIVATE_KEYSET_FILE || exit 1
$HYBRID_CLI get-public-key $PRIVATE_KEYSET_FILE $PUBLIC_KEYSET_FILE || exit 1
$HYBRID_CLI encrypt $PUBLIC_KEYSET_FILE $MESSAGE_FILE $CONTEXT_INFO_FILE $ENCRYPTED_MESSAGE_FILE || exit 1
$HYBRID_CLI decrypt $PRIVATE_KEYSET_FILE $OTHER_MESSAGE_FILE $CONTEXT_INFO_FILE $RESULT_FILE

EXIT_VALUE="$?"
assert_equal 1 "$EXIT_VALUE"

#############################################################################
#### Encrypt with wrong key.
test_name="encrypt_with_wrong_key"
echo "+++ Starting test $test_name..."

$HYBRID_CLI gen-private-key $PRIVATE_KEYSET_FILE || exit 1
$HYBRID_CLI encrypt $PRIVATE_KEYSET_FILE $MESSAGE_FILE $ENCRYPTED_MESSAGE_FILE

EXIT_VALUE="$?"
assert_equal 1 "$EXIT_VALUE"

#############################################################################
#### Decrypt with wrong key.
test_name="decrypt_with_wrong_key"
echo "+++ Starting test $test_name..."

$HYBRID_CLI gen-private-key $PRIVATE_KEYSET_FILE || exit 1
$HYBRID_CLI get-public-key $PRIVATE_KEYSET_FILE $PUBLIC_KEYSET_FILE || exit 1
$HYBRID_CLI encrypt $PUBLIC_KEYSET_FILE $MESSAGE_FILE $CONTEXT_INFO_FILE $ENCRYPTED_MESSAGE_FILE || exit 1
$HYBRID_CLI decrypt $PUBLIC_KEYSET_FILE $ENCRYPTED_MESSAGE_FILE $CONTEXT_INFO_FILE $RESULT_FILE

EXIT_VALUE="$?"
assert_equal 1 "$EXIT_VALUE"

#############################################################################
#### Decrypt with different context.
test_name="decrypt_with_different_context"
echo "+++ Starting test $test_name..."

$HYBRID_CLI gen-private-key $PRIVATE_KEYSET_FILE || exit 1
$HYBRID_CLI get-public-key $PRIVATE_KEYSET_FILE $PUBLIC_KEYSET_FILE || exit 1
$HYBRID_CLI encrypt $PUBLIC_KEYSET_FILE $MESSAGE_FILE $CONTEXT_INFO_FILE $ENCRYPTED_MESSAGE_FILE || exit 1
$HYBRID_CLI decrypt $PRIVATE_KEYSET_FILE $ENCRYPTED_MESSAGE_FILE $OTHER_CONTEXT_INFO_FILE $RESULT_FILE

EXIT_VALUE="$?"
assert_equal 1 "$EXIT_VALUE"
