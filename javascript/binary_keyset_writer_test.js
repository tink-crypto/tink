// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

goog.module('tink.BinaryKeysetWriterTest');
goog.setTestOnly('tink.BinaryKeysetWriterTest');

const BinaryKeysetReader = goog.require('tink.BinaryKeysetReader');
const BinaryKeysetWriter = goog.require('tink.BinaryKeysetWriter');
const testSuite = goog.require('goog.testing.testSuite');
const {createKeyset} = goog.require('tink.testUtils');

testSuite({
  testGetSerializedKeySet() {
    const dummyKeyset = createKeyset();

    // Write the keyset.
    const writer = new BinaryKeysetWriter();
    const serializedKeyset = writer.write(dummyKeyset);

    // Read the keyset proto serialization.
    const reader = BinaryKeysetReader.withUint8Array(serializedKeyset);
    const keysetFromReader = reader.read();

    // Test that it returns the same object as was created.
    assertObjectEquals(dummyKeyset, keysetFromReader);
  },
});
