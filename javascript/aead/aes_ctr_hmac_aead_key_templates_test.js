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

const {AesCtrHmacAeadKeyManager} = goog.require('google3.third_party.tink.javascript.aead.aes_ctr_hmac_aead_key_manager');
const {AesCtrHmacAeadKeyTemplates} = goog.require('google3.third_party.tink.javascript.aead.aes_ctr_hmac_aead_key_templates');
const {PbAesCtrHmacAeadKeyFormat, PbHashType, PbOutputPrefixType} = goog.require('google3.third_party.tink.javascript.internal.proto');

describe('aes ctr hmac aead key templates test', function() {
  it('aes128 ctr hmac sha256', function() {
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

    expect(keyTemplate.getTypeUrl()).toBe(expectedTypeUrl);
    expect(keyTemplate.getOutputPrefixType()).toBe(expectedOutputPrefix);

    // Test values in key format.
    const keyFormat = PbAesCtrHmacAeadKeyFormat.deserializeBinary(
        keyTemplate.getValue_asU8());

    // Test AesCtrKeyFormat.
    const aesCtrKeyFormat = keyFormat.getAesCtrKeyFormat();
    expect(aesCtrKeyFormat.getKeySize()).toBe(expectedAesKeySize);
    expect(aesCtrKeyFormat.getParams().getIvSize()).toBe(expectedIvSize);

    // Test HmacKeyFormat.
    const hmacKeyFormat = keyFormat.getHmacKeyFormat();
    expect(hmacKeyFormat.getKeySize()).toBe(expectedHmacKeySize);
    expect(hmacKeyFormat.getParams().getTagSize()).toBe(expectedTagSize);
    expect(hmacKeyFormat.getParams().getHash()).toBe(expectedHashFunction);

    // Test that the template works with AesCtrHmacAeadKeyManager.
    manager.getKeyFactory().newKey(keyTemplate.getValue_asU8());
  });

  it('aes256 ctr hmac sha256', function() {
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

    expect(keyTemplate.getTypeUrl()).toBe(expectedTypeUrl);
    expect(keyTemplate.getOutputPrefixType()).toBe(expectedOutputPrefix);

    // Test values in key format.
    const keyFormat = PbAesCtrHmacAeadKeyFormat.deserializeBinary(
        keyTemplate.getValue_asU8());

    // Test AesCtrKeyFormat.
    const aesCtrKeyFormat = keyFormat.getAesCtrKeyFormat();
    expect(aesCtrKeyFormat.getKeySize()).toBe(expectedAesKeySize);
    expect(aesCtrKeyFormat.getParams().getIvSize()).toBe(expectedIvSize);

    // Test HmacKeyFormat.
    const hmacKeyFormat = keyFormat.getHmacKeyFormat();
    expect(hmacKeyFormat.getKeySize()).toBe(expectedHmacKeySize);
    expect(hmacKeyFormat.getParams().getTagSize()).toBe(expectedTagSize);
    expect(hmacKeyFormat.getParams().getHash()).toBe(expectedHashFunction);

    // Test that the template works with AesCtrHmacAeadKeyManager.
    manager.getKeyFactory().newKey(keyTemplate.getValue_asU8());
  });
});
