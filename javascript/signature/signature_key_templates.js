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

goog.module('tink.signature.SignatureKeyTemplates');

const PbEcdsaKeyFormat = goog.require('proto.google.crypto.tink.EcdsaKeyFormat');
const PbEcdsaParams = goog.require('proto.google.crypto.tink.EcdsaParams');
const PbEcdsaSignatureEncoding = goog.require('proto.google.crypto.tink.EcdsaSignatureEncoding');
const PbEllipticCurveType = goog.require('proto.google.crypto.tink.EllipticCurveType');
const PbHashType = goog.require('proto.google.crypto.tink.HashType');
const PbKeyTemplate = goog.require('proto.google.crypto.tink.KeyTemplate');
const PbOutputPrefixType = goog.require('proto.google.crypto.tink.OutputPrefixType');
const SignatureConfig = goog.require('tink.signature.SignatureConfig');

/**
 * Pre-generated KeyTemplates for keys for digital signatures.
 *
 * One can use these templates to generate new Keyset with
 * KeysetHandle.generateNew method. To generate a new keyset that contains a
 * single EcdsaKey, one can do:
 *
 * SignatureConfig.Register();
 * KeysetHandle handle = KeysetHandle.generateNew(
 *     SignatureKeyTemplates.ecdsaP256());
 *
 * @final
 */
class SignatureKeyTemplates {
  /**
   * Returns a KeyTemplate that generates new instances of
   * EcdsaPrivateKey with the following parameters:
   *  Hash function: SHA256
   *  Curve: NIST P-256
   *  Signature encoding: DER (this is the encoding that Java uses)
   *  OutputPrefixType: TINK
   *
   * @return {!PbKeyTemplate}
   */
  static ecdsaP256() {
    return createEcdsaKeyTemplate(
        /* curveType = */ PbEllipticCurveType.NIST_P256,
        /* hashType = */ PbHashType.SHA256,
        /* encoding = */ PbEcdsaSignatureEncoding.DER,
        /* outputPrefixType = */ PbOutputPrefixType.TINK);
  }

  /**
   * Returns a KeyTemplate that generates new instances of
   * EcdsaPrivateKey with the following parameters:
   *  Hash function: SHA512
   *  Curve: NIST P-384
   *  Signature encoding: DER (this is the encoding that Java uses)
   *  OutputPrefixType: TINK
   *
   * @return {!PbKeyTemplate}
   */
  static ecdsaP384() {
    return createEcdsaKeyTemplate(
        /* curveType = */ PbEllipticCurveType.NIST_P384,
        /* hashType = */ PbHashType.SHA512,
        /* encoding = */ PbEcdsaSignatureEncoding.DER,
        /* outputPrefixType = */ PbOutputPrefixType.TINK);
  }

  /**
   * Returns a KeyTemplate that generates new instances of
   * EcdsaPrivateKey with the following parameters:
   *  Hash function: SHA512
   *  Curve: NIST P-521
   *  Signature encoding: DER (this is the encoding that Java uses).
   *  OutputPrefixType: TINK
   *
   * @return {!PbKeyTemplate}
   */
  static ecdsaP521() {
    return createEcdsaKeyTemplate(
        /* curveType = */ PbEllipticCurveType.NIST_P521,
        /* hashType = */ PbHashType.SHA512,
        /* encoding = */ PbEcdsaSignatureEncoding.DER,
        /* outputPrefixType = */ PbOutputPrefixType.TINK);
  }

  /**
   * Returns a KeyTemplate that generates new instances of
   * EcdsaPrivateKey with the following parameters:
   *  Hash function: SHA256
   *  Curve: NIST P-256
   *  Signature encoding: IEEE_P1363 (this is the encoding that WebCrypto uses)
   *  OutputPrefixType: TINK
   *
   * @return {!PbKeyTemplate}
   */
  static ecdsaP256IeeeEncoding() {
    return createEcdsaKeyTemplate(
        /* curveType = */ PbEllipticCurveType.NIST_P256,
        /* hashType = */ PbHashType.SHA256,
        /* encoding = */ PbEcdsaSignatureEncoding.IEEE_P1363,
        /* outputPrefixType = */ PbOutputPrefixType.TINK);
  }

  /**
   * Returns a KeyTemplate that generates new instances of
   * EcdsaPrivateKey with the following parameters:
   *  Hash function: SHA512
   *  Curve: NIST P-384
   *  Signature encoding: IEEE_P1363 (this is the encoding that WebCrypto uses)
   *  OutputPrefixType: TINK
   *
   * @return {!PbKeyTemplate}
   */
  static ecdsaP384IeeeEncoding() {
    return createEcdsaKeyTemplate(
        /* curveType = */ PbEllipticCurveType.NIST_P384,
        /* hashType = */ PbHashType.SHA512,
        /* encoding = */ PbEcdsaSignatureEncoding.IEEE_P1363,
        /* outputPrefixType = */ PbOutputPrefixType.TINK);
  }

  /**
   * Returns a KeyTemplate that generates new instances of
   * EcdsaPrivateKey with the following parameters:
   *  Hash function: SHA512
   *  Curve: NIST P-521
   *  Signature encoding: IEEE_P1363 (this is the encoding that WebCrypto uses)
   *  OutputPrefixType: TINK
   *
   * @return {!PbKeyTemplate}
   */
  static ecdsaP521IeeeEncoding() {
    return createEcdsaKeyTemplate(
        /* curveType = */ PbEllipticCurveType.NIST_P521,
        /* hashType = */ PbHashType.SHA512,
        /* encoding = */ PbEcdsaSignatureEncoding.IEEE_P1363,
        /* outputPrefixType = */ PbOutputPrefixType.TINK);
  }
}

/**
 * @param {!PbEllipticCurveType} curveType
 * @param {!PbHashType} hashType
 * @param {!PbEcdsaSignatureEncoding} encoding
 * @param {!PbOutputPrefixType} outputPrefixType
 *
 * @return {!PbKeyTemplate}
 */
const createEcdsaKeyTemplate = function(
    curveType, hashType, encoding, outputPrefixType) {
  // key format
  const keyFormat = new PbEcdsaKeyFormat();
  const params =
      new PbEcdsaParams().setCurve(curveType).setHashType(hashType).setEncoding(
          encoding);
  keyFormat.setParams(params);

  // key template
  const keyTemplate = new PbKeyTemplate()
                          .setTypeUrl(SignatureConfig.ECDSA_PRIVATE_KEY_TYPE)
                          .setValue(keyFormat.serializeBinary())
                          .setOutputPrefixType(outputPrefixType);

  return keyTemplate;
};

exports = SignatureKeyTemplates;
