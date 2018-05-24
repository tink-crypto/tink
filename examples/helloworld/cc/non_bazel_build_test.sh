#!/bin/bash

#############################################################################
##### Tests for hello_world binary.

ROOT_DIR="$TEST_SRCDIR/__main__"
MY_PROJECT_DIR="$TEST_TMPDIR/my_project"
HELLO_WORLD_SRC="$ROOT_DIR/examples/helloworld/cc/hello_world.cc"
KEYSET_FILE="$ROOT_DIR/examples/helloworld/cc/aes128_gcm_test_keyset_json.txt"
LIBTINK_SO_FILE="cc/libtink.so"
TINK_HEADERS_TAR_FILE="cc/tink_headers.tar"
TINK_DEPS_HEADERS_TAR_FILE="cc/tink_deps_headers.tar"

PLAINTEXT_FILE="$TEST_TMPDIR/example_plaintext.txt"
CIPHERTEXT_FILE="$TEST_TMPDIR/ciphertext.bin"
DECRYPTED_FILE="$TEST_TMPDIR/decrypted.txt"
AAD_TEXT="some associated data"

#############################################################################

##### Create directories for "my_project".
mkdir $MY_PROJECT_DIR
mkdir $MY_PROJECT_DIR/include
mkdir $MY_PROJECT_DIR/lib

##### Install libtink.so and header files.
cp -L $LIBTINK_SO_FILE $MY_PROJECT_DIR/lib/
tar xf $TINK_HEADERS_TAR_FILE -C $MY_PROJECT_DIR/include/
tar xf $TINK_DEPS_HEADERS_TAR_FILE -C $MY_PROJECT_DIR/include/

##### Create and compile "my_project".
cp $HELLO_WORLD_SRC $KEYSET_FILE $MY_PROJECT_DIR
cd $MY_PROJECT_DIR
export LD_RUN_PATH="$MY_PROJECT_DIR/lib/"
g++ -std=c++11 -Iinclude/ -Llib/ hello_world.cc -ltink

HELLO_WORLD_CLI="$MY_PROJECT_DIR/a.out"

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
