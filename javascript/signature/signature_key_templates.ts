/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {PbEcdsaKeyFormat, PbEcdsaParams, PbEcdsaSignatureEncoding, PbEllipticCurveType, PbHashType, PbKeyTemplate, PbOutputPrefixType} from '../internal/proto';

import * as SignatureConfig from './signature_config';

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
export class SignatureKeyTemplates {
  /**
   * Returns a KeyTemplate that generates new instances of
   * EcdsaPrivateKey with the following parameters:
   *  Hash function: SHA256
   *  Curve: NIST P-256
   *  Signature encoding: DER (this is the encoding that Java uses)
   *  OutputPrefixType: TINK
   *
   */
  static ecdsaP256(): PbKeyTemplate {
    return createEcdsaKeyTemplate(
        /* curveType = */
        PbEllipticCurveType.NIST_P256,
        /* hashType = */
        PbHashType.SHA256,
        /* encoding = */
        PbEcdsaSignatureEncoding.DER,
        /* outputPrefixType = */
        PbOutputPrefixType.TINK);
  }

  /**
   * Returns a KeyTemplate that generates new instances of
   * EcdsaPrivateKey with the following parameters:
   *  Hash function: SHA512
   *  Curve: NIST P-384
   *  Signature encoding: DER (this is the encoding that Java uses)
   *  OutputPrefixType: TINK
   *
   */
  static ecdsaP384(): PbKeyTemplate {
    return createEcdsaKeyTemplate(
        /* curveType = */
        PbEllipticCurveType.NIST_P384,
        /* hashType = */
        PbHashType.SHA512,
        /* encoding = */
        PbEcdsaSignatureEncoding.DER,
        /* outputPrefixType = */
        PbOutputPrefixType.TINK);
  }

  /**
   * Returns a KeyTemplate that generates new instances of
   * EcdsaPrivateKey with the following parameters:
   *  Hash function: SHA512
   *  Curve: NIST P-521
   *  Signature encoding: DER (this is the encoding that Java uses).
   *  OutputPrefixType: TINK
   *
   */
  static ecdsaP521(): PbKeyTemplate {
    return createEcdsaKeyTemplate(
        /* curveType = */
        PbEllipticCurveType.NIST_P521,
        /* hashType = */
        PbHashType.SHA512,
        /* encoding = */
        PbEcdsaSignatureEncoding.DER,
        /* outputPrefixType = */
        PbOutputPrefixType.TINK);
  }

  /**
   * Returns a KeyTemplate that generates new instances of
   * EcdsaPrivateKey with the following parameters:
   *  Hash function: SHA256
   *  Curve: NIST P-256
   *  Signature encoding: IEEE_P1363 (this is the encoding that WebCrypto uses)
   *  OutputPrefixType: TINK
   *
   */
  static ecdsaP256IeeeEncoding(): PbKeyTemplate {
    return createEcdsaKeyTemplate(
        /* curveType = */
        PbEllipticCurveType.NIST_P256,
        /* hashType = */
        PbHashType.SHA256,
        /* encoding = */
        PbEcdsaSignatureEncoding.IEEE_P1363,
        /* outputPrefixType = */
        PbOutputPrefixType.TINK);
  }

  /**
   * Returns a KeyTemplate that generates new instances of
   * EcdsaPrivateKey with the following parameters:
   *  Hash function: SHA512
   *  Curve: NIST P-384
   *  Signature encoding: IEEE_P1363 (this is the encoding that WebCrypto uses)
   *  OutputPrefixType: TINK
   *
   */
  static ecdsaP384IeeeEncoding(): PbKeyTemplate {
    return createEcdsaKeyTemplate(
        /* curveType = */
        PbEllipticCurveType.NIST_P384,
        /* hashType = */
        PbHashType.SHA512,
        /* encoding = */
        PbEcdsaSignatureEncoding.IEEE_P1363,
        /* outputPrefixType = */
        PbOutputPrefixType.TINK);
  }

  /**
   * Returns a KeyTemplate that generates new instances of
   * EcdsaPrivateKey with the following parameters:
   *  Hash function: SHA512
   *  Curve: NIST P-521
   *  Signature encoding: IEEE_P1363 (this is the encoding that WebCrypto uses)
   *  OutputPrefixType: TINK
   *
   */
  static ecdsaP521IeeeEncoding(): PbKeyTemplate {
    return createEcdsaKeyTemplate(
        /* curveType = */
        PbEllipticCurveType.NIST_P521,
        /* hashType = */
        PbHashType.SHA512,
        /* encoding = */
        PbEcdsaSignatureEncoding.IEEE_P1363,
        /* outputPrefixType = */
        PbOutputPrefixType.TINK);
  }
}

function createEcdsaKeyTemplate(
    curveType: PbEllipticCurveType, hashType: PbHashType,
    encoding: PbEcdsaSignatureEncoding,
    outputPrefixType: PbOutputPrefixType): PbKeyTemplate {
  // key format
  const keyFormat = new PbEcdsaKeyFormat();
  const params = (new PbEcdsaParams())
                     .setCurve(curveType)
                     .setHashType(hashType)
                     .setEncoding(encoding);
  keyFormat.setParams(params);

  // key template
  const keyTemplate = (new PbKeyTemplate())
                          .setTypeUrl(SignatureConfig.ECDSA_PRIVATE_KEY_TYPE)
                          .setValue(keyFormat.serializeBinary())
                          .setOutputPrefixType(outputPrefixType);
  return keyTemplate;
}
