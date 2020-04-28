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

set -ue

#############################################################################
##### Test for using Tink in a CMake project.
## This expects the following variables to be set:
## TEST_TMPDIR -- a temporary directory we can use
## TEST_DATA_DIR -- the directory in which the project with hello_world.cc
##                  can be found.
## TEST_SRCDIR -- The directory in which Tink is stored.

# XDG_CACHE_HOME must be set for a successful build of BoringSSL.
export XDG_CACHE_HOME="$TEST_TMPDIR/cache"
TEST_DATA_DIR="$TEST_SRCDIR/tink/examples/cc/helloworld"
CMAKE_LISTS_FILE="$TEST_DATA_DIR/CMakeLists_for_CMakeBuildTest.txt"
HELLO_WORLD_SRC="$TEST_DATA_DIR/hello_world.cc"
KEYSET_FILE="$TEST_DATA_DIR/aes128_gcm_test_keyset_json.txt"

PROJECT_DIR="$TEST_TMPDIR/my_project"
PLAINTEXT_FILE="$TEST_TMPDIR/example_plaintext.txt"
CIPHERTEXT_FILE="$TEST_TMPDIR/ciphertext.bin"
DECRYPTED_FILE="$TEST_TMPDIR/decrypted.txt"
AAD_TEXT="some associated data"

#############################################################################

##### Create necessary directories, and link Tink source.
mkdir -p $XDG_CACHE_HOME
mkdir -p $PROJECT_DIR $PROJECT_DIR/third_party
ln -s $TINK_SRC_DIR $PROJECT_DIR/third_party/tink

##### Copy "my_project" files.
cp $HELLO_WORLD_SRC $KEYSET_FILE $PROJECT_DIR
cp $CMAKE_LISTS_FILE $PROJECT_DIR/CMakeLists.txt

##### Build "my_project".
cd $PROJECT_DIR
mkdir build && cd build
# Record CMake version in the build log.
cmake --version
cmake .. -DCMAKE_CXX_STANDARD=11
make

##### Use the resulting hello_world application.
HELLO_WORLD_CLI="$PROJECT_DIR/build/hello_world"

# Create a plaintext.
echo "This is some message to be encrypted." > $PLAINTEXT_FILE

# Run encryption & decryption.
$HELLO_WORLD_CLI $KEYSET_FILE encrypt $PLAINTEXT_FILE "$AAD_TEXT" $CIPHERTEXT_FILE
$HELLO_WORLD_CLI $KEYSET_FILE decrypt $CIPHERTEXT_FILE "$AAD_TEXT" $DECRYPTED_FILE

# Check that decryption is correct.
diff -q $DECRYPTED_FILE $PLAINTEXT_FILE
if [ $? -ne 0 ]; then
  echo "--- Failure: the decrypted file differs from the original plaintext."
  diff $DECRYPTED_FILE $PLAINTEXT_FILE
  exit 1
fi
echo "+++ Success: decryption was correct."
