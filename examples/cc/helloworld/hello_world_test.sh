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

#!/bin/bash

#############################################################################
##### Tests for hello_world binary.

HELLO_WORLD_CLI="$1"
KEYSET_FILE="$2"
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
