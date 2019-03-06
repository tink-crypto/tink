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

goog.module('tink.hybrid.HybridKeyTemplatesTest');
goog.setTestOnly('tink.hybrid.HybridKeyTemplatesTest');

const AeadKeyTemplates = goog.require('tink.aead.AeadKeyTemplates');
const EciesAeadHkdfPrivateKeyManager = goog.require('tink.hybrid.EciesAeadHkdfPrivateKeyManager');
const HybridKeyTemplates = goog.require('tink.hybrid.HybridKeyTemplates');
const PbEciesAeadHkdfKeyFormat = goog.require('proto.google.crypto.tink.EciesAeadHkdfKeyFormat');
const PbEllipticCurveType = goog.require('proto.google.crypto.tink.EllipticCurveType');
const PbHashType = goog.require('proto.google.crypto.tink.HashType');
const PbOutputPrefixType = goog.require('proto.google.crypto.tink.OutputPrefixType');
const PbPointFormat = goog.require('proto.google.crypto.tink.EcPointFormat');

const testSuite = goog.require('goog.testing.testSuite');

testSuite({
  testEciesP256HkdfHmacSha256Aes128Gcm() {
    // Expects function to create a key with following parameters.
    const expectedCurve = PbEllipticCurveType.NIST_P256;
    const expectedHkdfHashFunction = PbHashType.SHA256;
    const expectedAeadTemplate = AeadKeyTemplates.aes128Gcm();
    const expectedPointFormat = PbPointFormat.UNCOMPRESSED;
    const expectedOutputPrefix = PbOutputPrefixType.TINK;

    // Expected type URL is the one supported by EciesAeadHkdfPrivateKeyManager.
    const manager = new EciesAeadHkdfPrivateKeyManager();
    const expectedTypeUrl = manager.getKeyType();

    const keyTemplate = HybridKeyTemplates.eciesP256HkdfHmacSha256Aes128Gcm();

    assertEquals(expectedTypeUrl, keyTemplate.getTypeUrl());
    assertEquals(expectedOutputPrefix, keyTemplate.getOutputPrefixType());

    // Test values in key format.
    const keyFormat =
        PbEciesAeadHkdfKeyFormat.deserializeBinary(keyTemplate.getValue());
    const params = keyFormat.getParams();
    assertEquals(expectedPointFormat, params.getEcPointFormat());

    // Test KEM params.
    const kemParams = params.getKemParams();
    assertEquals(expectedCurve, kemParams.getCurveType());
    assertEquals(expectedHkdfHashFunction, kemParams.getHkdfHashType());

    // Test DEM params.
    const demParams = params.getDemParams();
    assertObjectEquals(expectedAeadTemplate, demParams.getAeadDem());

    // Test that the template works with EciesAeadHkdfPrivateKeyManager.
    manager.getKeyFactory().newKey(keyTemplate.getValue_asU8());
  },

  testEciesP256HkdfHmacSha256Aes128CtrHmacSha256() {
    // Expects function to create a key with following parameters.
    const expectedCurve = PbEllipticCurveType.NIST_P256;
    const expectedHkdfHashFunction = PbHashType.SHA256;
    const expectedAeadTemplate = AeadKeyTemplates.aes128CtrHmacSha256();
    const expectedPointFormat = PbPointFormat.UNCOMPRESSED;
    const expectedOutputPrefix = PbOutputPrefixType.TINK;

    // Expected type URL is the one supported by EciesAeadHkdfPrivateKeyManager.
    const manager = new EciesAeadHkdfPrivateKeyManager();
    const expectedTypeUrl = manager.getKeyType();

    const keyTemplate =
        HybridKeyTemplates.eciesP256HkdfHmacSha256Aes128CtrHmacSha256();

    assertEquals(expectedTypeUrl, keyTemplate.getTypeUrl());
    assertEquals(expectedOutputPrefix, keyTemplate.getOutputPrefixType());

    // Test values in key format.
    const keyFormat =
        PbEciesAeadHkdfKeyFormat.deserializeBinary(keyTemplate.getValue());
    const params = keyFormat.getParams();
    assertEquals(expectedPointFormat, params.getEcPointFormat());

    // Test KEM params.
    const kemParams = params.getKemParams();
    assertEquals(expectedCurve, kemParams.getCurveType());
    assertEquals(expectedHkdfHashFunction, kemParams.getHkdfHashType());

    // Test DEM params.
    const demParams = params.getDemParams();
    assertObjectEquals(expectedAeadTemplate, demParams.getAeadDem());

    // Test that the template works with EciesAeadHkdfPrivateKeyManager.
    manager.getKeyFactory().newKey(keyTemplate.getValue_asU8());
  },
});
