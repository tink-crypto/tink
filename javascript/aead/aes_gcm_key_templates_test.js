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

goog.module('tink.aead.AesGcmKeyTemplatesTest');
goog.setTestOnly('tink.aead.AesGcmKeyTemplatesTest');

const AesGcmKeyManager = goog.require('tink.aead.AesGcmKeyManager');
const AesGcmKeyTemplates = goog.require('tink.aead.AesGcmKeyTemplates');
const PbAesGcmKeyFormat = goog.require('proto.google.crypto.tink.AesGcmKeyFormat');
const PbOutputPrefixType = goog.require('proto.google.crypto.tink.OutputPrefixType');

const testSuite = goog.require('goog.testing.testSuite');

testSuite({

  testAes128Gcm() {
    // The created key should have the following parameters.
    const expectedKeySize = 16;
    const expectedOutputPrefix = PbOutputPrefixType.TINK;
    // Expected type URL is the one supported by AesGcmKeyManager.
    const manager = new AesGcmKeyManager();
    const expectedTypeUrl = manager.getKeyType();

    const keyTemplate = AesGcmKeyTemplates.aes128Gcm();

    assertEquals(expectedTypeUrl, keyTemplate.getTypeUrl());
    assertEquals(expectedOutputPrefix, keyTemplate.getOutputPrefixType());

    // Test key size value in key format.
    const keyFormat =
        PbAesGcmKeyFormat.deserializeBinary(keyTemplate.getValue_asU8());
    assertEquals(expectedKeySize, keyFormat.getKeySize());

    // Test that the template works with AesCtrHmacAeadKeyManager.
    manager.getKeyFactory().newKey(keyTemplate.getValue_asU8());
  },

  testAes256Gcm() {
    // The created key should have the following parameters.
    const expectedKeySize = 32;
    const expectedOutputPrefix = PbOutputPrefixType.TINK;
    // Expected type URL is the one supported by AesGcmKeyManager.
    const manager = new AesGcmKeyManager();
    const expectedTypeUrl = manager.getKeyType();

    const keyTemplate = AesGcmKeyTemplates.aes256Gcm();

    assertEquals(expectedTypeUrl, keyTemplate.getTypeUrl());
    assertEquals(expectedOutputPrefix, keyTemplate.getOutputPrefixType());

    // Test key size value in key format.
    const keyFormat =
        PbAesGcmKeyFormat.deserializeBinary(keyTemplate.getValue_asU8());
    assertEquals(expectedKeySize, keyFormat.getKeySize());

    // Test that the template works with AesCtrHmacAeadKeyManager.
    manager.getKeyFactory().newKey(keyTemplate.getValue_asU8());
  },

  testAes256GcmNoPrefix() {
    // The created key should have the following parameters.
    const expectedKeySize = 32;
    const expectedOutputPrefix = PbOutputPrefixType.RAW;
    // Expected type URL is the one supported by AesGcmKeyManager.
    const manager = new AesGcmKeyManager();
    const expectedTypeUrl = manager.getKeyType();

    const keyTemplate = AesGcmKeyTemplates.aes256GcmNoPrefix();

    assertEquals(expectedTypeUrl, keyTemplate.getTypeUrl());
    assertEquals(expectedOutputPrefix, keyTemplate.getOutputPrefixType());

    // Test key size value in key format.
    const keyFormat =
        PbAesGcmKeyFormat.deserializeBinary(keyTemplate.getValue_asU8());
    assertEquals(expectedKeySize, keyFormat.getKeySize());

    // Test that the template works with AesCtrHmacAeadKeyManager.
    manager.getKeyFactory().newKey(keyTemplate.getValue_asU8());
  }
});
