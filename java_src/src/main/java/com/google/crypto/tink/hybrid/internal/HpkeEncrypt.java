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

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.proto.HpkeParams;
import com.google.crypto.tink.proto.HpkePublicKey;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;

/**
 * Hybrid Public Key Encryption (HPKE) encryption.
 *
 * <p>HPKE RFC: https://www.rfc-editor.org/rfc/rfc9180.html
 */
@Immutable
final class HpkeEncrypt implements HybridEncrypt {
  private static final byte[] EMPTY_ASSOCIATED_DATA = new byte[0];

  @SuppressWarnings("Immutable") // We copy this on creation and never output it.
  private final byte[] recipientPublicKey;

  private final HpkeKem kem;
  private final HpkeKdf kdf;
  private final HpkeAead aead;

  @SuppressWarnings("Immutable") // We copy this on creation and never output it.
  private final byte[] outputPrefix;

  private HpkeEncrypt(
      Bytes recipientPublicKey, HpkeKem kem, HpkeKdf kdf, HpkeAead aead, Bytes outputPrefix) {
    this.recipientPublicKey = recipientPublicKey.toByteArray();
    this.kem = kem;
    this.kdf = kdf;
    this.aead = aead;
    this.outputPrefix = outputPrefix.toByteArray();
  }

  @AccessesPartialKey
  static HybridEncrypt create(com.google.crypto.tink.hybrid.HpkePublicKey key)
      throws GeneralSecurityException {
    HpkeParameters parameters = key.getParameters();
    return new HpkeEncrypt(
        key.getPublicKeyBytes(),
        createKem(parameters.getKemId()),
        createKdf(parameters.getKdfId()),
        createAead(parameters.getAeadId()),
        key.getOutputPrefix());
  }

  static HpkeKem createKem(HpkeParameters.KemId kemId) throws GeneralSecurityException {
    if (kemId.equals(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)) {
      return new X25519HpkeKem(new HkdfHpkeKdf("HmacSha256"));
    }
    if (kemId.equals(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)) {
      return NistCurvesHpkeKem.fromCurve(EllipticCurves.CurveType.NIST_P256);
    }
    if (kemId.equals(HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384)) {
      return NistCurvesHpkeKem.fromCurve(EllipticCurves.CurveType.NIST_P384);
    }
    if (kemId.equals(HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512)) {
      return NistCurvesHpkeKem.fromCurve(EllipticCurves.CurveType.NIST_P521);
    }
    throw new GeneralSecurityException("Unrecognized HPKE KEM identifier");
  }

  static HpkeKdf createKdf(HpkeParameters.KdfId kdfId) throws GeneralSecurityException {
    if (kdfId.equals(HpkeParameters.KdfId.HKDF_SHA256)) {
      return new HkdfHpkeKdf("HmacSha256");
    }
    if (kdfId.equals(HpkeParameters.KdfId.HKDF_SHA384)) {
      return new HkdfHpkeKdf("HmacSha384");
    }
    if (kdfId.equals(HpkeParameters.KdfId.HKDF_SHA512)) {
      return new HkdfHpkeKdf("HmacSha512");
    }
    throw new GeneralSecurityException("Unrecognized HPKE KDF identifier");
  }

  static HpkeAead createAead(HpkeParameters.AeadId aeadId) throws GeneralSecurityException {
    if (aeadId.equals(HpkeParameters.AeadId.AES_128_GCM)) {
      return new AesGcmHpkeAead(16);
    }
    if (aeadId.equals(HpkeParameters.AeadId.AES_256_GCM)) {
      return new AesGcmHpkeAead(32);
    }
    if (aeadId.equals(HpkeParameters.AeadId.CHACHA20_POLY1305)) {
      return new ChaCha20Poly1305HpkeAead();
    }
    throw new GeneralSecurityException("Unrecognized HPKE AEAD identifier");
  }

  /** Returns an HPKE encryption primitive created from {@code recipientPublicKey} */
  static HpkeEncrypt createHpkeEncrypt(HpkePublicKey recipientPublicKey)
      throws GeneralSecurityException {
    if (recipientPublicKey.getPublicKey().isEmpty()) {
      throw new IllegalArgumentException("HpkePublicKey.public_key is empty.");
    }
    HpkeParams params = recipientPublicKey.getParams();
    HpkeKem kem = HpkePrimitiveFactory.createKem(params);
    HpkeKdf kdf = HpkePrimitiveFactory.createKdf(params);
    HpkeAead aead = HpkePrimitiveFactory.createAead(params);
    return new HpkeEncrypt(
        Bytes.copyFrom(recipientPublicKey.getPublicKey().toByteArray()),
        kem,
        kdf,
        aead,
        /* outputPrefix= */ Bytes.copyFrom(new byte[0]));
  }

  private byte[] noPrefixEncrypt(final byte[] plaintext, final byte[] contextInfo)
      throws GeneralSecurityException {
    byte[] info = contextInfo;
    if (info == null) {
      info = new byte[0];
    }
    HpkeContext context = HpkeContext.createSenderContext(recipientPublicKey, kem, kdf, aead, info);
    byte[] ciphertext = context.seal(plaintext, EMPTY_ASSOCIATED_DATA);
    return com.google.crypto.tink.subtle.Bytes.concat(context.getEncapsulatedKey(), ciphertext);
  }

  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] contextInfo)
      throws GeneralSecurityException {
    byte[] ciphertext = noPrefixEncrypt(plaintext, contextInfo);
    if (outputPrefix.length == 0) {
      return ciphertext;
    }
    return com.google.crypto.tink.subtle.Bytes.concat(outputPrefix, ciphertext);
  }
}
