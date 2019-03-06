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

goog.module('tink.CryptoFormatTest');
goog.setTestOnly('tink.CryptoFormatTest');

const CryptoFormat = goog.require('tink.CryptoFormat');
const PbKey = goog.require('proto.google.crypto.tink.Keyset.Key');
const PbOutputPrefixType = goog.require('proto.google.crypto.tink.OutputPrefixType');

const testSuite = goog.require('goog.testing.testSuite');

testSuite({
  async testConstants() {
    assertEquals(0, CryptoFormat.RAW_PREFIX_SIZE);
    assertEquals(5, CryptoFormat.NON_RAW_PREFIX_SIZE);
    assertEquals(5, CryptoFormat.LEGACY_PREFIX_SIZE);
    assertEquals(5, CryptoFormat.TINK_PREFIX_SIZE);

    assertEquals(0x00, CryptoFormat.LEGACY_START_BYTE);
    assertEquals(0x01, CryptoFormat.TINK_START_BYTE);
  },

  async testGetOutputPrefixUnknownPrefixType() {
    let key = new PbKey();
    key.setOutputPrefixType(PbOutputPrefixType.UNKNOWN_PREFIX);
    key.setKeyId(0xAABBCCDD);

    try {
      CryptoFormat.getOutputPrefix(key);
    } catch (e) {
      assertEquals('CustomError: Unsupported key prefix type.', e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testGetOutputPrefixInvalidKeyId() {
    // Key id has to be an unsigned 32-bit integer.
    const invalidKeyIds = [0.2, -10, 2**32];
    let key = new PbKey();
    key.setOutputPrefixType(PbOutputPrefixType.TINK);

    const invalidKeyIdsLength = invalidKeyIds.length;
    for (let i = 0; i < invalidKeyIdsLength; i++) {
      key.setKeyId(invalidKeyIds[i]);
      try {
        CryptoFormat.getOutputPrefix(key);
      } catch (e) {
        assertEquals('CustomError: Number has to be unsigned 32-bit integer.',
            e.toString());
        continue;
      }
      fail('An exception should be thrown for i: ' + i + '.');
    }
  },

  async testGetOutputPrefixTink() {
    let key = new PbKey();
    key.setOutputPrefixType(PbOutputPrefixType.TINK);
    key.setKeyId(0xAABBCCDD);
    const expectedResult =
        new Uint8Array([CryptoFormat.TINK_START_BYTE, 0xAA, 0xBB, 0xCC, 0xDD]);

    const actualResult = CryptoFormat.getOutputPrefix(key);
    assertObjectEquals(expectedResult, actualResult);
  },

  async testGetOutputPrefixLegacy() {
    let key = new PbKey();
    key.setOutputPrefixType(PbOutputPrefixType.LEGACY);
    key.setKeyId(0x01020304);
    const expectedResult = new Uint8Array(
        [CryptoFormat.LEGACY_START_BYTE, 0x01, 0x02, 0x03, 0x04]);

    const actualResult = CryptoFormat.getOutputPrefix(key);
    assertObjectEquals(expectedResult, actualResult);
  },

  async testGetOutputPrefixRaw() {
    let key = new PbKey();
    key.setOutputPrefixType(PbOutputPrefixType.RAW);
    key.setKeyId(0x16154211);
    const expectedResult = new Uint8Array(0);

    const actualResult = CryptoFormat.getOutputPrefix(key);
    assertObjectEquals(expectedResult, actualResult);
  },
});
