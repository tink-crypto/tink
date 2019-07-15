#!/bin/bash
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
##### Tests for file_mac python example.

ROOT_DIR="$TEST_SRCDIR/tink"
FILE_MAC_CLI="$ROOT_DIR/examples/file_mac/python/file_mac"

KEYSET_FILE="$ROOT_DIR/examples/file_mac/python/hmac_sha256_256bittag_test_keyset.json"
DATA_FILE="$TEST_TMPDIR/example_data.txt"
EXPECTED_MAC_FILE="$TEST_TMPDIR/expected_mac.txt"

#############################################################################

##### Create a plaintext.
echo "This is some message to be verified." > $DATA_FILE
echo "01293CE659EBCFB08AF02C9B2E564D8352CD8EB58A363E7DE62BAA0BED9CA92BD257F76F4F" > $EXPECTED_MAC_FILE

##### Run verification
$FILE_MAC_CLI $KEYSET_FILE $DATA_FILE $EXPECTED_MAC_FILE

##### Check that it exited successfully
if [ $? -ne 0 ]; then
  echo "--- Failure: the MAC outputs did not match"
  exit 1
fi
echo "+++ Success: MAC outputs matched."
