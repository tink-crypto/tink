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

goog.module('tink.hybrid.HybridKeyTemplates');

const AeadKeyTemplates = goog.require('tink.aead.AeadKeyTemplates');
const HybridConfig = goog.require('tink.hybrid.HybridConfig');
const PbEciesAeadDemParams = goog.require('proto.google.crypto.tink.EciesAeadDemParams');
const PbEciesAeadHkdfKeyFormat = goog.require('proto.google.crypto.tink.EciesAeadHkdfKeyFormat');
const PbEciesAeadHkdfParams = goog.require('proto.google.crypto.tink.EciesAeadHkdfParams');
const PbEciesHkdfKemParams = goog.require('proto.google.crypto.tink.EciesHkdfKemParams');
const PbEllipticCurveType = goog.require('proto.google.crypto.tink.EllipticCurveType');
const PbHashType = goog.require('proto.google.crypto.tink.HashType');
const PbKeyTemplate = goog.require('proto.google.crypto.tink.KeyTemplate');
const PbOutputPrefixType = goog.require('proto.google.crypto.tink.OutputPrefixType');
const PbPointFormat = goog.require('proto.google.crypto.tink.EcPointFormat');

/**
 * Pre-generated KeyTemplates for keys for hybrid encryption.
 *
 * One can use these templates to generate new Keyset with
 * KeysetHandle.generateNew method. To generate a new keyset that contains a
 * single EciesAeadHkdfKey, one can do:
 *
 * HybridConfig.Register();
 * KeysetHandle handle = KeysetHandle.generateNew(
 *     HybridKeyTemplates.eciesP256HkdfHmacSha256Aes128Gcm());
 *
 * @final
 */
class HybridKeyTemplates {
  /**
   * Returns a KeyTemplate that generates new instances of
   * EciesAeadHkdfPrivateKey with the following parameters:
   *
   *   KEM: ECDH over NIST P-256
   *   DEM: AES128-GCM
   *   KDF: HKDF-HMAC-SHA256 with an empty salt
   *   OutputPrefixType: TINK
   *
   * @return {!PbKeyTemplate}
   */
  static eciesP256HkdfHmacSha256Aes128Gcm() {
    return createEciesAeadHkdfKeyTemplate_(
        /* curveType = */ PbEllipticCurveType.NIST_P256,
        /* hkdfHash = */ PbHashType.SHA256,
        /* pointFormat = */ PbPointFormat.UNCOMPRESSED,
        /* demKeyTemplate = */ AeadKeyTemplates.aes128Gcm(),
        /* hkdfSalt = */ new Uint8Array(0));
  }

  /**
   * Returns a KeyTemplate that generates new instances of
   * EciesAeadHkdfPrivateKey with the following parameters:
   *
   *   KEM: ECDH over NIST P-256
   *   DEM: AES128-CTR-HMAC-SHA256 with
   *        - AES key size: 16 bytes
   *        - AES CTR IV size: 16 bytes
   *        - HMAC key size: 32 bytes
   *        - HMAC tag size: 16 bytes
   *   KDF: HKDF-HMAC-SHA256 with an empty salt
   *   OutputPrefixType: TINK
   *
   * @return {!PbKeyTemplate}
   */
  static eciesP256HkdfHmacSha256Aes128CtrHmacSha256() {
    return createEciesAeadHkdfKeyTemplate_(
        /* curveType = */ PbEllipticCurveType.NIST_P256,
        /* hkdfHash = */ PbHashType.SHA256,
        /* pointFormat = */ PbPointFormat.UNCOMPRESSED,
        /* demKeyTemplate = */ AeadKeyTemplates.aes128CtrHmacSha256(),
        /* hkdfSalt = */ new Uint8Array(0));
  }
}

/**
 * @param {!PbEllipticCurveType} curveType
 * @param {!PbHashType} hkdfHash
 * @param {!PbPointFormat} pointFormat
 * @param {!PbKeyTemplate} demKeyTemplate
 * @param {!Uint8Array} hkdfSalt
 *
 * @return {!PbKeyTemplate}
 * @private
 */
const createEciesAeadHkdfKeyTemplate_ = function(
    curveType, hkdfHash, pointFormat, demKeyTemplate, hkdfSalt) {
  // key format
  const keyFormat =
      new PbEciesAeadHkdfKeyFormat().setParams(createEciesAeadHkdfParams_(
          curveType, hkdfHash, pointFormat, demKeyTemplate, hkdfSalt));

  // key template
  const keyTemplate =
      new PbKeyTemplate()
          .setTypeUrl(HybridConfig.ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE)
          .setValue(keyFormat.serializeBinary())
          .setOutputPrefixType(PbOutputPrefixType.TINK);

  return keyTemplate;
};

/**
 * @param {!PbEllipticCurveType} curveType
 * @param {!PbHashType} hkdfHash
 * @param {!PbPointFormat} pointFormat
 * @param {!PbKeyTemplate} demKeyTemplate
 * @param {!Uint8Array} hkdfSalt
 *
 * @return {!PbEciesAeadHkdfParams}
 * @private
 */
const createEciesAeadHkdfParams_ = function(
    curveType, hkdfHash, pointFormat, demKeyTemplate, hkdfSalt) {
  // KEM params
  const kemParams = new PbEciesHkdfKemParams()
                        .setCurveType(curveType)
                        .setHkdfHashType(hkdfHash)
                        .setHkdfSalt(hkdfSalt);

  // DEM params
  const demParams = new PbEciesAeadDemParams().setAeadDem(demKeyTemplate);

  // params
  const params = new PbEciesAeadHkdfParams()
                     .setKemParams(kemParams)
                     .setDemParams(demParams)
                     .setEcPointFormat(pointFormat);

  return params;
};

exports = HybridKeyTemplates;
