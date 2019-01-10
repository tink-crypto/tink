// Copyright 2017 Google Inc.
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

import com.google.crypto.tink.proto.EcdsaKeyFormat;
import com.google.crypto.tink.proto.EcdsaParams;
import com.google.crypto.tink.proto.EcdsaSignatureEncoding;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.proto.RsaSsaPkcs1KeyFormat;
import com.google.crypto.tink.proto.RsaSsaPkcs1Params;
import com.google.crypto.tink.proto.RsaSsaPssKeyFormat;
import com.google.crypto.tink.proto.RsaSsaPssParams;
import com.google.protobuf.ByteString;
import java.math.BigInteger;
import java.security.spec.RSAKeyGenParameterSpec;

/**
 * Pre-generated {@link KeyTemplate} for {@link com.google.crypto.tink.PublicKeySign} and {@link
 * com.google.crypto.tink.PublicKeyVerify}.
 *
 * <p>One can use these templates to generate new {@link com.google.crypto.tink.proto.Keyset} with
 * {@link com.google.crypto.tink.KeysetHandle}. To generate a new keyset that contains a single
 * {@code EcdsaPrivateKey}, one can do:
 *
 * <pre>{@code
 * Config.register(SignatureConfig.TINK_1_1_0);
 * KeysetHandle handle = KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256);
 * PublicKeySign signer = PublicKeySignFactory.getPrimitive(handle);
 * }</pre>
 *
 * @since 1.0.0
 */
public final class SignatureKeyTemplates {
  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.EcdsaPrivateKey} with the following parameters:
   *
   * <ul>
   *   <li>Hash function: SHA256
   *   <li>Curve: NIST P-256
   *   <li>Signature encoding: DER (this is the encoding that Java uses).
   * </ul>
   */
  public static final KeyTemplate ECDSA_P256 =
      createEcdsaKeyTemplate(
          HashType.SHA256, EllipticCurveType.NIST_P256, EcdsaSignatureEncoding.DER);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.EcdsaPrivateKey} with the following parameters:
   *
   * <ul>
   *   <li>Hash function: SHA512
   *   <li>Curve: NIST P-384
   *   <li>Signature encoding: DER (this is the encoding that Java uses).
   * </ul>
   */
  public static final KeyTemplate ECDSA_P384 =
      createEcdsaKeyTemplate(
          HashType.SHA512, EllipticCurveType.NIST_P384, EcdsaSignatureEncoding.DER);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.EcdsaPrivateKey} with the following parameters:
   *
   * <ul>
   *   <li>Hash function: SHA512
   *   <li>Curve: NIST P-521
   *   <li>Signature encoding: DER (this is the encoding that Java uses).
   * </ul>
   */
  public static final KeyTemplate ECDSA_P521 =
      createEcdsaKeyTemplate(
          HashType.SHA512, EllipticCurveType.NIST_P521, EcdsaSignatureEncoding.DER);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.EcdsaPrivateKey} with the following parameters:
   *
   * <ul>
   *   <li>Hash function: SHA256
   *   <li>Curve: NIST P-256
   *   <li>Signature encoding: IEEE_P1363 (this is the encoding that JWS and WebCrypto use).
   * </ul>
   */
  public static final KeyTemplate ECDSA_P256_IEEE_P1363 =
      createEcdsaKeyTemplate(
          HashType.SHA256, EllipticCurveType.NIST_P256, EcdsaSignatureEncoding.IEEE_P1363);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.EcdsaPrivateKey} with the following parameters:
   *
   * <ul>
   *   <li>Hash function: SHA512
   *   <li>Curve: NIST P-384
   *   <li>Signature encoding: IEEE_P1363 (this is the encoding that JWS and WebCrypto use).
   * </ul>
   */
  public static final KeyTemplate ECDSA_P384_IEEE_P1363 =
      createEcdsaKeyTemplate(
          HashType.SHA512, EllipticCurveType.NIST_P384, EcdsaSignatureEncoding.IEEE_P1363);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.EcdsaPrivateKey} with the following parameters:
   *
   * <ul>
   *   <li>Hash function: SHA512
   *   <li>Curve: NIST P-521
   *   <li>Signature encoding: IEEE_P1363 (this is the encoding that JWS and WebCrypto use).
   * </ul>
   */
  public static final KeyTemplate ECDSA_P521_IEEE_P1363 =
      createEcdsaKeyTemplate(
          HashType.SHA512, EllipticCurveType.NIST_P521, EcdsaSignatureEncoding.IEEE_P1363);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.Ed25519PrivateKey}.
   *
   * @since 1.1.0
   */
  public static final KeyTemplate ED25519 =
      KeyTemplate.newBuilder()
          .setTypeUrl(Ed25519PrivateKeyManager.TYPE_URL)
          .setOutputPrefixType(OutputPrefixType.TINK)
          .build();

  /**
   * @return a {@link KeyTemplate} containing a {@link EcdsaKeyFormat} with some specified
   *     parameters.
   */
  public static KeyTemplate createEcdsaKeyTemplate(
      HashType hashType, EllipticCurveType curve, EcdsaSignatureEncoding encoding) {
    EcdsaParams params =
        EcdsaParams.newBuilder()
            .setHashType(hashType)
            .setCurve(curve)
            .setEncoding(encoding)
            .build();
    EcdsaKeyFormat format = EcdsaKeyFormat.newBuilder().setParams(params).build();
    return KeyTemplate.newBuilder()
        .setValue(format.toByteString())
        .setTypeUrl(EcdsaSignKeyManager.TYPE_URL)
        .setOutputPrefixType(OutputPrefixType.TINK)
        .build();
  }

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey} with the following parameters:
   *
   * <ul>
   *   <li>Hash function: SHA256.
   *   <li>Modulus size: 3072 bit.
   *   <li>Public exponent: 65537 (aka F4).
   * </ul>
   */
  public static final KeyTemplate RSA_SSA_PKCS1_3072_SHA256_F4 =
      createRsaSsaPkcs1KeyTemplate(HashType.SHA256, 3072, RSAKeyGenParameterSpec.F4);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey} with the following parameters:
   *
   * <ul>
   *   <li>Hash function: SHA512.
   *   <li>Modulus size: 4096 bit.
   *   <li>Public exponent: 65537 (aka F4).
   * </ul>
   */
  public static final KeyTemplate RSA_SSA_PKCS1_4096_SHA512_F4 =
      createRsaSsaPkcs1KeyTemplate(HashType.SHA512, 4096, RSAKeyGenParameterSpec.F4);

  /**
   * @return a {@link KeyTemplate} containing a {@link RsaSsaPkcs1KeyFormat} with some specified
   *     parameters.
   */
  public static KeyTemplate createRsaSsaPkcs1KeyTemplate(
      HashType hashType, int modulusSize, BigInteger publicExponent) {
    RsaSsaPkcs1Params params = RsaSsaPkcs1Params.newBuilder().setHashType(hashType).build();
    RsaSsaPkcs1KeyFormat format =
        RsaSsaPkcs1KeyFormat.newBuilder()
            .setParams(params)
            .setModulusSizeInBits(modulusSize)
            .setPublicExponent(ByteString.copyFrom(publicExponent.toByteArray()))
            .build();
    return KeyTemplate.newBuilder()
        .setValue(format.toByteString())
        .setTypeUrl(RsaSsaPkcs1SignKeyManager.TYPE_URL)
        .setOutputPrefixType(OutputPrefixType.TINK)
        .build();
  }

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.RsaSsaPssPrivateKey} with the following parameters:
   *
   * <ul>
   *   <li>Signature hash: SHA256.
   *   <li>MGF1 hash: SHA256.
   *   <li>Salt length: 32 (i.e., SHA256's output length).
   *   <li>Modulus size: 3072 bit.
   *   <li>Public exponent: 65537 (aka F4).
   * </ul>
   */
  public static final KeyTemplate RSA_SSA_PSS_3072_SHA256_SHA256_32_F4 =
      createRsaSsaPssKeyTemplate(
          HashType.SHA256, HashType.SHA256, 32, 3072, RSAKeyGenParameterSpec.F4);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.RsaSsaPssPrivateKey} with the following parameters:
   *
   * <ul>
   *   <li>Signature hash: SHA512.
   *   <li>MGF1 hash: SHA512.
   *   <li>Salt length: 64 (i.e., SHA512's output length).
   *   <li>Modulus size: 4096 bit.
   *   <li>Public exponent: 65537 (aka F4).
   * </ul>
   */
  public static final KeyTemplate RSA_SSA_PSS_4096_SHA512_SHA512_64_F4 =
      createRsaSsaPssKeyTemplate(
          HashType.SHA512, HashType.SHA512, 64, 4096, RSAKeyGenParameterSpec.F4);

  /**
   * @return a {@link KeyTemplate} containing a {@link RsaSsaPssKeyFormat} with some specified
   *     parameters.
   */
  public static KeyTemplate createRsaSsaPssKeyTemplate(
      HashType sigHash,
      HashType mgf1Hash,
      int saltLength,
      int modulusSize,
      BigInteger publicExponent) {
    RsaSsaPssParams params =
        RsaSsaPssParams.newBuilder()
            .setSigHash(sigHash)
            .setMgf1Hash(mgf1Hash)
            .setSaltLength(saltLength)
            .build();
    RsaSsaPssKeyFormat format =
        RsaSsaPssKeyFormat.newBuilder()
            .setParams(params)
            .setModulusSizeInBits(modulusSize)
            .setPublicExponent(ByteString.copyFrom(publicExponent.toByteArray()))
            .build();
    return KeyTemplate.newBuilder()
        .setValue(format.toByteString())
        .setTypeUrl(RsaSsaPssSignKeyManager.TYPE_URL)
        .setOutputPrefixType(OutputPrefixType.TINK)
        .build();
  }
}
