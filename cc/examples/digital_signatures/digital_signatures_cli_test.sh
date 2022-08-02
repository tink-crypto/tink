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
#### Tests for digital_signatures_cli binary.

SIGNATURE_CLI="$1"

PRIVATE_KEYSET_FILE="$TEST_TMPDIR/private_keyset.bin"
PUBLIC_KEYSET_FILE="$TEST_TMPDIR/public_keyset.bin"
MESSAGE_FILE="$TEST_TMPDIR/message.txt"
SIGNATURE_FILE="$TEST_TMPDIR/signature.bin"
RESULT_FILE="$TEST_TMPDIR/result.txt"

OTHER_PRIVATE_KEYSET_FILE="$TEST_TMPDIR/other_private_keyset.bin"
OTHER_PUBLIC_KEYSET_FILE="$TEST_TMPDIR/other_public_keyset.bin"
OTHER_MESSAGE_FILE="$TEST_TMPDIR/other_message.txt"

echo "This is a message." > $MESSAGE_FILE
echo "This is a different message." > $OTHER_MESSAGE_FILE

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
$SIGNATURE_CLI gen-private-key $PRIVATE_KEYSET_FILE || exit 1
$SIGNATURE_CLI get-public-key $PRIVATE_KEYSET_FILE $PUBLIC_KEYSET_FILE || exit 1

#### Sign the message.
$SIGNATURE_CLI sign $PRIVATE_KEYSET_FILE $MESSAGE_FILE $SIGNATURE_FILE || exit 1

#### Verify the signature.
$SIGNATURE_CLI verify $PUBLIC_KEYSET_FILE $MESSAGE_FILE $SIGNATURE_FILE $RESULT_FILE || exit 1

#### Check that the signature is valid.
RESULT=$(<$RESULT_FILE)
assert_equal "valid" "$RESULT"

#############################################################################
#### Bad private key when getting the public key.
test_name="get_public_key_with_bad_private_key"
echo "+++ Starting test $test_name..."

echo "abcd" >> $PRIVATE_KEYSET_FILE
$SIGNATURE_CLI get-public-key $PRIVATE_KEYSET_FILE $PUBLIC_KEYSET_FILE

EXIT_VALUE="$?"
assert_equal 1 "$EXIT_VALUE"

#############################################################################
#### Different public key when verifying a signature.
test_name="verify_with_different_public_key"
echo "+++ Starting test $test_name..."

$SIGNATURE_CLI gen-private-key $PRIVATE_KEYSET_FILE || exit 1
$SIGNATURE_CLI gen-private-key $OTHER_PRIVATE_KEYSET_FILE || exit 1
$SIGNATURE_CLI get-public-key $OTHER_PRIVATE_KEYSET_FILE $OTHER_PUBLIC_KEYSET_FILE || exit 1
$SIGNATURE_CLI sign $PRIVATE_KEYSET_FILE $MESSAGE_FILE $SIGNATURE_FILE || exit 1
$SIGNATURE_CLI verify $OTHER_PUBLIC_KEYSET_FILE $MESSAGE_FILE $SIGNATURE_FILE $RESULT_FILE || exit 1

RESULT=$(<$RESULT_FILE)
assert_equal "invalid" "$RESULT"

#############################################################################
#### Different message when verifying a signature.
test_name="verify_with_different_message"
echo "+++ Starting test $test_name..."

$SIGNATURE_CLI gen-private-key $PRIVATE_KEYSET_FILE || exit 1
$SIGNATURE_CLI get-public-key $PRIVATE_KEYSET_FILE $PUBLIC_KEYSET_FILE || exit 1
$SIGNATURE_CLI sign $PRIVATE_KEYSET_FILE $MESSAGE_FILE $SIGNATURE_FILE || exit 1
$SIGNATURE_CLI verify $PUBLIC_KEYSET_FILE $OTHER_MESSAGE_FILE $SIGNATURE_FILE $RESULT_FILE || exit 1

RESULT=$(<$RESULT_FILE)
assert_equal "invalid" "$RESULT"

#############################################################################
#### Sign with wrong key.
test_name="sign_with_wrong_key"
echo "+++ Starting test $test_name..."

$SIGNATURE_CLI gen-private-key $PRIVATE_KEYSET_FILE || exit 1
$SIGNATURE_CLI get-public-key $PRIVATE_KEYSET_FILE $PUBLIC_KEYSET_FILE || exit 1
$SIGNATURE_CLI sign $PUBLIC_KEYSET_FILE $MESSAGE_FILE $SIGNATURE_FILE

EXIT_VALUE="$?"
assert_equal 1 "$EXIT_VALUE"

#############################################################################
#### Verify with wrong key.
test_name="verify_with_wrong_key"
echo "+++ Starting test $test_name..."

$SIGNATURE_CLI gen-private-key $PRIVATE_KEYSET_FILE || exit 1
$SIGNATURE_CLI sign $PRIVATE_KEYSET_FILE $MESSAGE_FILE $SIGNATURE_FILE || exit 1
$SIGNATURE_CLI verify $PRIVATE_KEYSET_FILE $MESSAGE_FILE $SIGNATURE_FILE $RESULT_FILE

EXIT_VALUE="$?"
assert_equal 1 "$EXIT_VALUE"
