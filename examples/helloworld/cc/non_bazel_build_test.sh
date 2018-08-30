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

#############################################################################
##### Tests for installing and using Tink in a non-Bazel project.

ROOT_DIR="$TEST_SRCDIR/tink"
TARGET_DIR="$TEST_TMPDIR/my_project"
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
mkdir -p $TARGET_DIR $TARGET_DIR/include $TARGET_DIR/lib

##### Install libtink.so and header files.
cp -L $LIBTINK_SO_FILE $TARGET_DIR/lib/
tar xf $TINK_HEADERS_TAR_FILE -C $TARGET_DIR/include/
tar xf $TINK_DEPS_HEADERS_TAR_FILE -C $TARGET_DIR/include/

##### Create and compile "my_project".
export LIBRARY_PATH=$LIBRARY_PATH:$TARGET_DIR/lib
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$TARGET_DIR/lib
cp $HELLO_WORLD_SRC $KEYSET_FILE $TARGET_DIR
cd $TARGET_DIR
g++ -std=c++11 -I$TARGET_DIR/include/ -L$TARGET_DIR/lib/ hello_world.cc -ltink -o hello_world

HELLO_WORLD_CLI="$TARGET_DIR/hello_world"

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
