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
const {PbAesGcmKeyFormat, PbOutputPrefixType} = goog.require('google3.third_party.tink.javascript.internal.proto');

describe('aes gcm key templates test', function() {
  it('aes128 gcm', function() {
    // The created key should have the following parameters.
    const expectedKeySize = 16;
    const expectedOutputPrefix = PbOutputPrefixType.TINK;
    // Expected type URL is the one supported by AesGcmKeyManager.
    const manager = new AesGcmKeyManager();
    const expectedTypeUrl = manager.getKeyType();

    const keyTemplate = AesGcmKeyTemplates.aes128Gcm();

    expect(keyTemplate.getTypeUrl()).toBe(expectedTypeUrl);
    expect(keyTemplate.getOutputPrefixType()).toBe(expectedOutputPrefix);

    // Test key size value in key format.
    const keyFormat =
        PbAesGcmKeyFormat.deserializeBinary(keyTemplate.getValue_asU8());
    expect(keyFormat.getKeySize()).toBe(expectedKeySize);

    // Test that the template works with AesCtrHmacAeadKeyManager.
    manager.getKeyFactory().newKey(keyTemplate.getValue_asU8());
  });

  it('aes256 gcm', function() {
    // The created key should have the following parameters.
    const expectedKeySize = 32;
    const expectedOutputPrefix = PbOutputPrefixType.TINK;
    // Expected type URL is the one supported by AesGcmKeyManager.
    const manager = new AesGcmKeyManager();
    const expectedTypeUrl = manager.getKeyType();

    const keyTemplate = AesGcmKeyTemplates.aes256Gcm();

    expect(keyTemplate.getTypeUrl()).toBe(expectedTypeUrl);
    expect(keyTemplate.getOutputPrefixType()).toBe(expectedOutputPrefix);

    // Test key size value in key format.
    const keyFormat =
        PbAesGcmKeyFormat.deserializeBinary(keyTemplate.getValue_asU8());
    expect(keyFormat.getKeySize()).toBe(expectedKeySize);

    // Test that the template works with AesCtrHmacAeadKeyManager.
    manager.getKeyFactory().newKey(keyTemplate.getValue_asU8());
  });

  it('aes256 gcm no prefix', function() {
    // The created key should have the following parameters.
    const expectedKeySize = 32;
    const expectedOutputPrefix = PbOutputPrefixType.RAW;
    // Expected type URL is the one supported by AesGcmKeyManager.
    const manager = new AesGcmKeyManager();
    const expectedTypeUrl = manager.getKeyType();

    const keyTemplate = AesGcmKeyTemplates.aes256GcmNoPrefix();

    expect(keyTemplate.getTypeUrl()).toBe(expectedTypeUrl);
    expect(keyTemplate.getOutputPrefixType()).toBe(expectedOutputPrefix);

    // Test key size value in key format.
    const keyFormat =
        PbAesGcmKeyFormat.deserializeBinary(keyTemplate.getValue_asU8());
    expect(keyFormat.getKeySize()).toBe(expectedKeySize);

    // Test that the template works with AesCtrHmacAeadKeyManager.
    manager.getKeyFactory().newKey(keyTemplate.getValue_asU8());
  });
});
