// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.hybrid.internal;

import static com.google.crypto.tink.internal.Util.isPrefix;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.proto.HpkeParams;
import com.google.crypto.tink.proto.HpkePrivateKey;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Hybrid Public Key Encryption (HPKE) decryption.
 *
 * <p>HPKE RFC: https://www.rfc-editor.org/rfc/rfc9180.html
 */
@Immutable
final class HpkeDecrypt implements HybridDecrypt {
  private static final byte[] EMPTY_ASSOCIATED_DATA = new byte[0];

  private final HpkeKemPrivateKey recipientPrivateKey;
  private final HpkeKem kem;
  private final HpkeKdf kdf;
  private final HpkeAead aead;
  private final int encapsulatedKeyLength;

  @SuppressWarnings("Immutable") // We copy this on creation and never output it.
  private final byte[] outputPrefix;

  private HpkeDecrypt(
      HpkeKemPrivateKey recipientPrivateKey,
      HpkeKem kem,
      HpkeKdf kdf,
      HpkeAead aead,
      int encapsulatedKeyLength,
      Bytes outputPrefix) {
    this.recipientPrivateKey = recipientPrivateKey;
    this.kem = kem;
    this.kdf = kdf;
    this.aead = aead;
    this.encapsulatedKeyLength = encapsulatedKeyLength;
    this.outputPrefix = outputPrefix.toByteArray();
  }

  /**
   * Returns the encapsulated key length (in bytes) for the specified {@code kemProtoEnum}. This
   * value corresponds to the 'Nenc' column in the following table.
   *
   * <p>https://www.rfc-editor.org/rfc/rfc9180.html#name-key-encapsulation-mechanism.
   */
  private static int encodingSizeInBytes(com.google.crypto.tink.proto.HpkeKem kemProtoEnum) {
    switch (kemProtoEnum) {
      case DHKEM_X25519_HKDF_SHA256:
        return 32;
      case DHKEM_P256_HKDF_SHA256:
        return 65;
      case DHKEM_P384_HKDF_SHA384:
        return 97;
      case DHKEM_P521_HKDF_SHA512:
        return 133;
      default:
        throw new IllegalArgumentException(
            "Unable to determine KEM-encoding length for " + kemProtoEnum.name());
    }
  }

  private static int encodingSizeInBytes(HpkeParameters.KemId kemId)
      throws GeneralSecurityException {
    if (kemId.equals(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)) {
      return 32;
    }
    if (kemId.equals(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)) {
      return 65;
    }
    if (kemId.equals(HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384)) {
      return 97;
    }
    if (kemId.equals(HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512)) {
      return 133;
    }
    throw new GeneralSecurityException("Unrecognized HPKE KEM identifier");
  }

  static EllipticCurves.CurveType nistHpkeKemToCurve(HpkeParameters.KemId kemId)
      throws GeneralSecurityException {
    if (kemId.equals(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)) {
      return EllipticCurves.CurveType.NIST_P256;
    }
    if (kemId.equals(HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384)) {
      return EllipticCurves.CurveType.NIST_P384;
    }
    if (kemId.equals(HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512)) {
      return EllipticCurves.CurveType.NIST_P521;
    }
    throw new GeneralSecurityException("Unrecognized NIST HPKE KEM identifier");
  }

  @AccessesPartialKey
  private static HpkeKemPrivateKey createHpkeKemPrivateKey(
      com.google.crypto.tink.hybrid.HpkePrivateKey privateKey) throws GeneralSecurityException {
    HpkeParameters.KemId kemId = privateKey.getParameters().getKemId();
    if (kemId.equals(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)) {
      return X25519HpkeKemPrivateKey.fromBytes(
          privateKey.getPrivateKeyBytes().toByteArray(InsecureSecretKeyAccess.get()));
    }
    if (kemId.equals(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
        || kemId.equals(HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384)
        || kemId.equals(HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512)) {
      return NistCurvesHpkeKemPrivateKey.fromBytes(
          privateKey.getPrivateKeyBytes().toByteArray(InsecureSecretKeyAccess.get()),
          privateKey.getPublicKey().getPublicKeyBytes().toByteArray(),
          nistHpkeKemToCurve(kemId));
    }
    throw new GeneralSecurityException("Unrecognized HPKE KEM identifier");
  }

  static HybridDecrypt create(com.google.crypto.tink.hybrid.HpkePrivateKey privateKey)
      throws GeneralSecurityException {
    HpkeParameters parameters = privateKey.getParameters();
    HpkeKem kem = HpkeEncrypt.createKem(parameters.getKemId());
    HpkeKdf kdf = HpkeEncrypt.createKdf(parameters.getKdfId());
    HpkeAead aead = HpkeEncrypt.createAead(parameters.getAeadId());
    int encapsulatedKeyLength = encodingSizeInBytes(parameters.getKemId());
    HpkeKemPrivateKey recipientKemPrivateKey = createHpkeKemPrivateKey(privateKey);
    return new HpkeDecrypt(
        recipientKemPrivateKey,
        kem,
        kdf,
        aead,
        encapsulatedKeyLength,
        privateKey.getOutputPrefix());
  }

  /** Returns an HPKE decryption primitive created from {@code recipientPrivateKey} */
  static HpkeDecrypt createHpkeDecrypt(HpkePrivateKey recipientPrivateKey)
      throws GeneralSecurityException {
    if (!recipientPrivateKey.hasPublicKey()) {
      throw new IllegalArgumentException("HpkePrivateKey is missing public_key field.");
    }
    if (!recipientPrivateKey.getPublicKey().hasParams()) {
      throw new IllegalArgumentException("HpkePrivateKey.public_key is missing params field.");
    }
    if (recipientPrivateKey.getPrivateKey().isEmpty()) {
      throw new IllegalArgumentException("HpkePrivateKey.private_key is empty.");
    }
    HpkeParams params = recipientPrivateKey.getPublicKey().getParams();
    HpkeKem kem = HpkePrimitiveFactory.createKem(params);
    HpkeKdf kdf = HpkePrimitiveFactory.createKdf(params);
    HpkeAead aead = HpkePrimitiveFactory.createAead(params);
    int encapsulatedKeyLength = encodingSizeInBytes(params.getKem());
    HpkeKemPrivateKey recipientKemPrivateKey = HpkeKemKeyFactory.createPrivate(recipientPrivateKey);
    return new HpkeDecrypt(
        recipientKemPrivateKey,
        kem,
        kdf,
        aead,
        encapsulatedKeyLength,
        /* outputPrefix= */ Bytes.copyFrom(new byte[0]));
  }

  private byte[] decryptNoPrefix(final byte[] ciphertext, final byte[] contextInfo)
      throws GeneralSecurityException {
    if (ciphertext.length < encapsulatedKeyLength) {
      throw new GeneralSecurityException("Ciphertext is too short.");
    }
    byte[] info = contextInfo;
    if (info == null) {
      info = new byte[0];
    }
    byte[] encapsulatedKey = Arrays.copyOf(ciphertext, encapsulatedKeyLength);
    byte[] aeadCiphertext =
        Arrays.copyOfRange(ciphertext, encapsulatedKeyLength, ciphertext.length);
    HpkeContext context =
        HpkeContext.createRecipientContext(
            encapsulatedKey, recipientPrivateKey, kem, kdf, aead, info);
    return context.open(aeadCiphertext, EMPTY_ASSOCIATED_DATA);
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] contextInfo)
      throws GeneralSecurityException {
    if (outputPrefix.length == 0) {
      return decryptNoPrefix(ciphertext, contextInfo);
    }
    if (!isPrefix(outputPrefix, ciphertext)) {
      throw new GeneralSecurityException("Invalid ciphertext (output prefix mismatch)");
    }
    byte[] ciphertextNoPrefix =
        Arrays.copyOfRange(ciphertext, outputPrefix.length, ciphertext.length);
    return decryptNoPrefix(ciphertextNoPrefix, contextInfo);
  }
}
