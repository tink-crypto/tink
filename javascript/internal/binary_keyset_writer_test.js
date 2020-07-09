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

const {BinaryKeysetReader} = goog.require('google3.third_party.tink.javascript.internal.binary_keyset_reader');
const {BinaryKeysetWriter} = goog.require('google3.third_party.tink.javascript.internal.binary_keyset_writer');
const {createKeyset} = goog.require('google3.third_party.tink.javascript.testing.internal.test_utils');

describe('binary keyset writer test', function() {
  it('get serialized key set', function() {
    const dummyKeyset = createKeyset();

    // Write the keyset.
    const writer = new BinaryKeysetWriter();
    const serializedKeyset = writer.write(dummyKeyset);

    // Read the keyset proto serialization.
    const reader = BinaryKeysetReader.withUint8Array(serializedKeyset);
    const keysetFromReader = reader.read();

    // Test that it returns the same object as was created.
    expect(keysetFromReader).toEqual(dummyKeyset);
  });
});
