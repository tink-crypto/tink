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
   *   <li>Curve: NIST P-384
   *   <li>Signature encoding: DER (this is the encoding that Java uses).
   * </ul>
   */
  public static final KeyTemplate ECDSA_P521 =
      createEcdsaKeyTemplate(
          HashType.SHA512, EllipticCurveType.NIST_P521, EcdsaSignatureEncoding.DER);

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
   * @return a {@link KeyTemplate} containing a {@link HmacKeyFormat} with some specified
   *     parameters.
   */
  public static KeyTemplate createEcdsaKeyTemplate(
      HashType hashType, EllipticCurveType curve, EcdsaSignatureEncoding encoding) {
    EcdsaParams params = EcdsaParams.newBuilder()
        .setHashType(hashType)
        .setCurve(curve)
        .setEncoding(encoding)
        .build();
    EcdsaKeyFormat format = EcdsaKeyFormat.newBuilder()
        .setParams(params)
        .build();
    return KeyTemplate.newBuilder()
        .setValue(format.toByteString())
        .setTypeUrl(EcdsaSignKeyManager.TYPE_URL)
        .setOutputPrefixType(OutputPrefixType.TINK)
        .build();
  }
}
