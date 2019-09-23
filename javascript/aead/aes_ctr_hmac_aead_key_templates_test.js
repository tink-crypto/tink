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

goog.module('tink.aead.AesCtrHmacAeadKeyTemplatesTest');
goog.setTestOnly('tink.aead.AesCtrHmacAeadKeyTemplatesTest');

const AesCtrHmacAeadKeyManager = goog.require('tink.aead.AesCtrHmacAeadKeyManager');
const AesCtrHmacAeadKeyTemplates = goog.require('tink.aead.AesCtrHmacAeadKeyTemplates');
const PbAesCtrHmacAeadKeyFormat = goog.require('proto.google.crypto.tink.AesCtrHmacAeadKeyFormat');
const PbHashType = goog.require('proto.google.crypto.tink.HashType');
const PbOutputPrefixType = goog.require('proto.google.crypto.tink.OutputPrefixType');

const testSuite = goog.require('goog.testing.testSuite');

testSuite({

  testAes128CtrHmacSha256() {
    // Expects function to create key with following parameters.
    const expectedAesKeySize = 16;
    const expectedIvSize = 16;
    const expectedHmacKeySize = 32;
    const expectedTagSize = 16;
    const expectedHashFunction = PbHashType.SHA256;
    const expectedOutputPrefix = PbOutputPrefixType.TINK;

    // Expected type URL is the one supported by AesCtrHmacAeadKeyManager.
    const manager = new AesCtrHmacAeadKeyManager();
    const expectedTypeUrl = manager.getKeyType();

    const keyTemplate = AesCtrHmacAeadKeyTemplates.aes128CtrHmacSha256();

    assertEquals(expectedTypeUrl, keyTemplate.getTypeUrl());
    assertEquals(expectedOutputPrefix, keyTemplate.getOutputPrefixType());

    // Test values in key format.
    const keyFormat = PbAesCtrHmacAeadKeyFormat.deserializeBinary(
        keyTemplate.getValue_asU8());

    // Test AesCtrKeyFormat.
    const aesCtrKeyFormat = keyFormat.getAesCtrKeyFormat();
    assertEquals(expectedAesKeySize, aesCtrKeyFormat.getKeySize());
    assertEquals(expectedIvSize, aesCtrKeyFormat.getParams().getIvSize());

    // Test HmacKeyFormat.
    const hmacKeyFormat = keyFormat.getHmacKeyFormat();
    assertEquals(expectedHmacKeySize, hmacKeyFormat.getKeySize());
    assertEquals(expectedTagSize, hmacKeyFormat.getParams().getTagSize());
    assertEquals(expectedHashFunction, hmacKeyFormat.getParams().getHash());

    // Test that the template works with AesCtrHmacAeadKeyManager.
    manager.getKeyFactory().newKey(keyTemplate.getValue_asU8());
  },

  testAes256CtrHmacSha256() {
    // Expects function to create key with following parameters.
    const expectedAesKeySize = 32;
    const expectedIvSize = 16;
    const expectedHmacKeySize = 32;
    const expectedTagSize = 32;
    const expectedHashFunction = PbHashType.SHA256;
    const expectedOutputPrefix = PbOutputPrefixType.TINK;

    // Expected type URL is the one supported by AesCtrHmacAeadKeyManager.
    const manager = new AesCtrHmacAeadKeyManager();
    const expectedTypeUrl = manager.getKeyType();

    const keyTemplate = AesCtrHmacAeadKeyTemplates.aes256CtrHmacSha256();

    assertEquals(expectedTypeUrl, keyTemplate.getTypeUrl());
    assertEquals(expectedOutputPrefix, keyTemplate.getOutputPrefixType());

    // Test values in key format.
    const keyFormat = PbAesCtrHmacAeadKeyFormat.deserializeBinary(
        keyTemplate.getValue_asU8());

    // Test AesCtrKeyFormat.
    const aesCtrKeyFormat = keyFormat.getAesCtrKeyFormat();
    assertEquals(expectedAesKeySize, aesCtrKeyFormat.getKeySize());
    assertEquals(expectedIvSize, aesCtrKeyFormat.getParams().getIvSize());

    // Test HmacKeyFormat.
    const hmacKeyFormat = keyFormat.getHmacKeyFormat();
    assertEquals(expectedHmacKeySize, hmacKeyFormat.getKeySize());
    assertEquals(expectedTagSize, hmacKeyFormat.getParams().getTagSize());
    assertEquals(expectedHashFunction, hmacKeyFormat.getParams().getHash());

    // Test that the template works with AesCtrHmacAeadKeyManager.
    manager.getKeyFactory().newKey(keyTemplate.getValue_asU8());
  },
});
