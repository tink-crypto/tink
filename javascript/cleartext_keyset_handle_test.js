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

goog.module('tink.CleartextKeysetHandleTest');
goog.setTestOnly();

const CleartextKeysetHandle = goog.require('tink.CleartextKeysetHandle');
const KeysetHandle = goog.require('tink.KeysetHandle');
const PbKeyset = goog.require('proto.google.crypto.tink.Keyset');
const testSuite = goog.require('goog.testing.testSuite');
const {createKeyset} = goog.require('tink.testUtils');

testSuite({
  testParseFromLightweightShouldWork() {
    assertTrue(
        CleartextKeysetHandle.fromJspbArray(createKeyset().toArray()) instanceof
        KeysetHandle);
  },

  testParseFromLightweightEmptyKeyset() {
    const keysetJspbArray = new PbKeyset().toArray();
    assertEquals(
        'CustomError: ' +
            'Keyset should be non null and must contain at least one key.',
        assertThrows(() => {
          CleartextKeysetHandle.fromJspbArray(keysetJspbArray);
        }).toString());
  },

  testDeserializeFromJspb() {
    const keyset1 = createKeyset();
    const keysetHandle =
        CleartextKeysetHandle.deserializeFromJspb(keyset1.serialize());
    const keyset2 = keysetHandle.getKeyset();
    assertEquals(keyset1.getPrimaryKeyId(), keyset2.getPrimaryKeyId());
    assertObjectEquals(keyset2.getKeyList(), keyset2.getKeyList());
  },

  testSerializeToJspb() {
    const keyset = createKeyset();
    const keysetHandle = new KeysetHandle(keyset);

    const keysetString = CleartextKeysetHandle.serializeToJspb(keysetHandle);
    assertEquals(keysetString, keyset.serialize());
  },

  testDeserializeFromBinary() {
    const keyset1 = createKeyset();
    const keysetHandle =
        CleartextKeysetHandle.deserializeFromBinary(keyset1.serializeBinary());
    const keyset2 = keysetHandle.getKeyset();
    assertEquals(keyset1.getPrimaryKeyId(), keyset2.getPrimaryKeyId());
    assertObjectEquals(keyset2.getKeyList(), keyset2.getKeyList());
  },

  testSerializeToBinary() {
    const keyset = createKeyset();
    const keysetHandle = new KeysetHandle(keyset);

    const keysetBinary = CleartextKeysetHandle.serializeToBinary(keysetHandle);
    assertObjectEquals(keysetBinary, keyset.serializeBinary());
  },
});
