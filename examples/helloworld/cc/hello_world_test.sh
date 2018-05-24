#!/bin/bash

#############################################################################
##### Tests for hello_world binary.

ROOT_DIR="$TEST_SRCDIR/__main__"
HELLO_WORLD_CLI="$ROOT_DIR/examples/helloworld/cc/hello_world"

KEYSET_FILE="$ROOT_DIR/examples/helloworld/cc/aes128_gcm_test_keyset_json.txt"
PLAINTEXT_FILE="$TEST_TMPDIR/example_plaintext.txt"
CIPHERTEXT_FILE="$TEST_TMPDIR/ciphertext.bin"
DECRYPTED_FILE="$TEST_TMPDIR/decrypted.txt"
AAD_TEXT="some associated data"

#############################################################################

##### Create a plaintext.
echo "This is some message to be encrypted." > $PLAINTEXT_FILE

##### Run encryption & decryption.
$HELLO_WORLD_CLI $KEYSET_FILE encrypt $PLAINTEXT_FILE "$AAD_TEXT" $CIPHERTEXT_FILE
$HELLO_WORLD_CLI $KEYSET_FILE decrypt $CIPHERTEXT_FILE "$AAD_TEXT" $DECRYPTED_FILE

##### Check that decryption is correct.
diff -q $DECRYPTED_FILE $PLAINTEXT_FILE
if [ $? -ne 0 ]; then
  echo "--- Failure: the decrypted file differs from the original plaintext."
  diff $DECRYPTED_FILE $PLAINTEXT_FILE
  exit 1
fi
echo "+++ Success: decryption was correct."
