// Copyright 2023 Google LLC
//
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

package com.google.crypto.tink.signature;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

/**
 * Pre-generated {@link Parameter} objects for {@link com.google.crypto.tink.PublicKeySign} and
 * {@link com.google.crypto.tink.PublicKeyVerify}. keys.
 *
 * <p>Note: if you want to keep dependencies small, consider inlining the constants here.
 */
public final class PredefinedSignatureParameters {
  /**
   * A {@link Parameters} object that generates new instances of {@link EcdsaPrivateKey} objects
   * with the following parameters:
   *
   * <ul>
   *   <li>Hash function: SHA256
   *   <li>Curve: NIST P-256
   *   <li>Signature encoding: DER (this is the encoding that Java uses).
   *   <li>Prefix type: {@link OutputPrefixType.TINK}
   * </ul>
   */
  public static final EcdsaParameters ECDSA_P256 =
      exceptionIsBug(
          () ->
              EcdsaParameters.builder()
                  .setHashType(EcdsaParameters.HashType.SHA256)
                  .setCurveType(EcdsaParameters.CurveType.NIST_P256)
                  .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
                  .setVariant(EcdsaParameters.Variant.TINK)
                  .build());

  /**
   * A {@link Parameters} that generates new instances of {@link EcdsaPrivateKey} objects with the
   * following parameters:
   *
   * <ul>
   *   <li>Hash function: SHA512
   *   <li>Curve: NIST P-384
   *   <li>Signature encoding: DER (this is the encoding that Java uses).
   *   <li>Prefix type: {@link OutputPrefixType.TINK}
   * </ul>
   */
  public static final EcdsaParameters ECDSA_P384 =
      exceptionIsBug(
          () ->
              EcdsaParameters.builder()
                  .setHashType(EcdsaParameters.HashType.SHA512)
                  .setCurveType(EcdsaParameters.CurveType.NIST_P384)
                  .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
                  .setVariant(EcdsaParameters.Variant.TINK)
                  .build());

  /**
   * A {@link Parameters} that generates new instances of {@link EcdsaPrivateKey} objects with the
   * following parameters:
   *
   * <ul>
   *   <li>Hash function: SHA512
   *   <li>Curve: NIST P-521
   *   <li>Signature encoding: DER (this is the encoding that Java uses).
   *   <li>Prefix type: {@link OutputPrefixType.TINK}
   * </ul>
   */
  public static final EcdsaParameters ECDSA_P521 =
      exceptionIsBug(
          () ->
              EcdsaParameters.builder()
                  .setHashType(EcdsaParameters.HashType.SHA512)
                  .setCurveType(EcdsaParameters.CurveType.NIST_P521)
                  .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
                  .setVariant(EcdsaParameters.Variant.TINK)
                  .build());

  /**
   * A {@link Parameters} that generates new instances of {@link EcdsaPrivateKey} objects with the
   * following parameters:
   *
   * <ul>
   *   <li>Hash function: SHA256
   *   <li>Curve: NIST P-256
   *   <li>Signature encoding: IEEE_P1363 (this is the encoding that JWS and WebCrypto use).
   *   <li>Prefix type: {@link OutputPrefixType.TINK}
   * </ul>
   */
  public static final EcdsaParameters ECDSA_P256_IEEE_P1363 =
      exceptionIsBug(
          () ->
              EcdsaParameters.builder()
                  .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                  .setCurveType(EcdsaParameters.CurveType.NIST_P256)
                  .setHashType(EcdsaParameters.HashType.SHA256)
                  .setVariant(EcdsaParameters.Variant.TINK)
                  .build());

  /**
   * A {@link Parameters} that generates new instances of {@link EcdsaPrivateKey} objects with the
   * following parameters:
   *
   * <ul>
   *   <li>Hash function: SHA512
   *   <li>Curve: NIST P-384
   *   <li>Signature encoding: IEEE_P1363 (this is the encoding that JWS and WebCrypto use).
   *   <li>Prefix type: {@link OutputPrefixType.TINK}
   * </ul>
   */
  public static final EcdsaParameters ECDSA_P384_IEEE_P1363 =
      exceptionIsBug(
          () ->
              EcdsaParameters.builder()
                  .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                  .setCurveType(EcdsaParameters.CurveType.NIST_P384)
                  .setHashType(EcdsaParameters.HashType.SHA512)
                  .setVariant(EcdsaParameters.Variant.TINK)
                  .build());

  /**
   * A {@link Parameters} that generates new instances of {@link EcdsaPrivateKey} objects with the
   * following parameters:
   *
   * <ul>
   *   <li>Hash function: SHA256
   *   <li>Curve: NIST P-256
   *   <li>Signature encoding: DER (this is the encoding that Java uses).
   *   <li>Prefix type: None
   * </ul>
   *
   * The digital signature generated by this key would be 64 bytes exactly.
   */
  public static final EcdsaParameters ECDSA_P256_IEEE_P1363_WITHOUT_PREFIX =
      exceptionIsBug(
          () ->
              EcdsaParameters.builder()
                  .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                  .setCurveType(EcdsaParameters.CurveType.NIST_P256)
                  .setHashType(EcdsaParameters.HashType.SHA256)
                  .setVariant(EcdsaParameters.Variant.NO_PREFIX)
                  .build());

  /**
   * A {@link Parameters} that generates new instances of {@link EcdsaPrivateKey} objects with the
   * following parameters:
   *
   * <ul>
   *   <li>Hash function: SHA512
   *   <li>Curve: NIST P-521
   *   <li>Signature encoding: IEEE_P1363 (this is the encoding that JWS and WebCrypto use).
   *   <li>Prefix type: {@link OutputPrefixType.TINK}
   * </ul>
   */
  public static final EcdsaParameters ECDSA_P521_IEEE_P1363 =
      exceptionIsBug(
          () ->
              EcdsaParameters.builder()
                  .setHashType(EcdsaParameters.HashType.SHA512)
                  .setCurveType(EcdsaParameters.CurveType.NIST_P521)
                  .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                  .setVariant(EcdsaParameters.Variant.TINK)
                  .build());

  /**
   * A {@link Parameters} that generates new instances of {@link Ed25519PrivateKey} objects.
   *
   * @since 1.1.0
   */
  public static final Ed25519Parameters ED25519 =
      exceptionIsBug(() -> Ed25519Parameters.create(Ed25519Parameters.Variant.TINK));

  /**
   * A {@link Parameters} that generates new instances of {@link ED25519PrivateKey}.
   *
   * <p>The difference between {@link ED25519WithRawOutput} and {@link ED25519} is the format of
   * signatures generated. {@link ED25519WithRawOutput} generates signatures of {@link
   * OutputPrefixType.RAW} format, which is 64 bytes long.
   *
   * @since 1.3.0
   */
  public static final Ed25519Parameters ED25519WithRawOutput =
      exceptionIsBug(() -> Ed25519Parameters.create(Ed25519Parameters.Variant.NO_PREFIX));

  /**
   * A {@link Parameters} that generates new instances of {@link RsaSsaPkcs1PrivateKey} objects with
   * the following parameters:
   *
   * <ul>
   *   <li>Hash function: SHA256.
   *   <li>Modulus size: 3072 bit.
   *   <li>Public exponent: 65537 (aka F4).
   *   <li>Prefix type: {@link OutputPrefixType.TINK}
   * </ul>
   */
  public static final RsaSsaPkcs1Parameters RSA_SSA_PKCS1_3072_SHA256_F4 =
      exceptionIsBug(
          () ->
              RsaSsaPkcs1Parameters.builder()
                  .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
                  .setModulusSizeBits(3072)
                  .setPublicExponent(RsaSsaPkcs1Parameters.F4)
                  .setVariant(RsaSsaPkcs1Parameters.Variant.TINK)
                  .build());

  /**
   * A {@link Parameters} that generates new instances of {@link RsaSsaPkcs1PrivateKey} objects with
   * the following parameters:
   *
   * <ul>
   *   <li>Hash function: SHA256.
   *   <li>Modulus size: 3072 bit.
   *   <li>Public exponent: 65537 (aka F4).
   *   <li>Prefix type: None
   * </ul>
   */
  public static final RsaSsaPkcs1Parameters RSA_SSA_PKCS1_3072_SHA256_F4_WITHOUT_PREFIX =
      exceptionIsBug(
          () ->
              RsaSsaPkcs1Parameters.builder()
                  .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
                  .setModulusSizeBits(3072)
                  .setPublicExponent(RsaSsaPkcs1Parameters.F4)
                  .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                  .build());

  /**
   * A {@link Parameters} that generates new instances of {@link RsaSsaPkcs1PrivateKey} objects with
   * the following parameters:
   *
   * <ul>
   *   <li>Hash function: SHA512.
   *   <li>Modulus size: 4096 bit.
   *   <li>Public exponent: 65537 (aka F4).
   *   <li>Prefix type: {@link OutputPrefixType.TINK}
   * </ul>
   */
  public static final RsaSsaPkcs1Parameters RSA_SSA_PKCS1_4096_SHA512_F4 =
      exceptionIsBug(
          () ->
              RsaSsaPkcs1Parameters.builder()
                  .setHashType(RsaSsaPkcs1Parameters.HashType.SHA512)
                  .setModulusSizeBits(4096)
                  .setPublicExponent(RsaSsaPkcs1Parameters.F4)
                  .setVariant(RsaSsaPkcs1Parameters.Variant.TINK)
                  .build());

  /**
   * A {@link Parameters} that generates new instances of {@link RsaSsaPssPrivateKey} objects with
   * the following parameters:
   *
   * <ul>
   *   <li>Signature hash: SHA256.
   *   <li>MGF1 hash: SHA256.
   *   <li>Salt length: 32 (i.e., SHA256's output length).
   *   <li>Modulus size: 3072 bit.
   *   <li>Public exponent: 65537 (aka F4).
   * </ul>
   */
  public static final RsaSsaPssParameters RSA_SSA_PSS_3072_SHA256_SHA256_32_F4 =
      exceptionIsBug(
          () ->
              RsaSsaPssParameters.builder()
                  .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
                  .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
                  .setSaltLengthBytes(32)
                  .setModulusSizeBits(3072)
                  .setPublicExponent(RsaSsaPssParameters.F4)
                  .setVariant(RsaSsaPssParameters.Variant.TINK)
                  .build());

  /**
   * A {@link Parameters} that generates new instances of {@link RsaSsaPssPrivateKey} objects with
   * the following parameters:
   *
   * <ul>
   *   <li>Signature hash: SHA512.
   *   <li>MGF1 hash: SHA512.
   *   <li>Salt length: 64 (i.e., SHA512's output length).
   *   <li>Modulus size: 4096 bit.
   *   <li>Public exponent: 65537 (aka F4).
   * </ul>
   */
  public static final RsaSsaPssParameters RSA_SSA_PSS_4096_SHA512_SHA512_64_F4 =
      exceptionIsBug(
          () ->
              RsaSsaPssParameters.builder()
                  .setSigHashType(RsaSsaPssParameters.HashType.SHA512)
                  .setMgf1HashType(RsaSsaPssParameters.HashType.SHA512)
                  .setSaltLengthBytes(64)
                  .setModulusSizeBits(4096)
                  .setPublicExponent(RsaSsaPssParameters.F4)
                  .setVariant(RsaSsaPssParameters.Variant.TINK)
                  .build());

  private PredefinedSignatureParameters() {}
}
