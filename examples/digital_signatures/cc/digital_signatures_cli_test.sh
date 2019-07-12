#!/bin/bash

#############################################################################
#### Tests for digital_signatures_cli binary.

ROOT_DIR="$TEST_SRCDIR/tink"
DIGITAL_SIGNATURES_CLI="$ROOT_DIR/examples/digital_signatures/cc/digital_signatures_cli"

PRIVATE_KEYSET_FILE="$TEST_TMPDIR/private_keyset.bin"
PUBLIC_KEYSET_FILE="$TEST_TMPDIR/public_keyset.bin"
MESSAGE_FILE="$TEST_TMPDIR/message.txt"
SIGNATURE_FILE="$TEST_TMPDIR/signature.bin"
RESULT_FILE="$TEST_TMPDIR/result.txt"

#############################################################################

#### Genetate a private key and get a public key.
$DIGITAL_SIGNATURES_CLI gen-private-key $PRIVATE_KEYSET_FILE
$DIGITAL_SIGNATURES_CLI get-public-key $PRIVATE_KEYSET_FILE $PUBLIC_KEYSET_FILE

#### Create a message.
echo "This is a message." > $MESSAGE_FILE

#### Sign the message.
$DIGITAL_SIGNATURES_CLI sign $PRIVATE_KEYSET_FILE $MESSAGE_FILE $SIGNATURE_FILE

#### Verify the signature.
$DIGITAL_SIGNATURES_CLI verify $PUBLIC_KEYSET_FILE $MESSAGE_FILE $SIGNATURE_FILE $RESULT_FILE

#### Check that the signature is valid.
RESULT=$(<$RESULT_FILE)
if [ $RESULT == "valid" ]; then
  echo "+++ Success: signature is valid."
else
  echo "--- Failure: signature is not valid."
  exit 1
fi
