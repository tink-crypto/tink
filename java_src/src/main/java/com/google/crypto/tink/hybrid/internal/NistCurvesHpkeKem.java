// Copyright 2022 Google LLC
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

import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EllipticCurves.CurveType;
import com.google.crypto.tink.subtle.EllipticCurves.PointFormatType;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

/** Diffie-Hellman-based P-256, P-384 and P-521 HPKE KEM variant. */
@Immutable
final class NistCurvesHpkeKem implements HpkeKem {
  private final CurveType curve;
  private final HkdfHpkeKdf hkdf;

  /** Construct HPKE KEM using {@code curve}. */
  static NistCurvesHpkeKem fromCurve(CurveType curve) throws GeneralSecurityException {
    switch (curve) {
      case NIST_P256:
        return new NistCurvesHpkeKem(new HkdfHpkeKdf("HmacSha256"), CurveType.NIST_P256);
      case NIST_P384:
        return new NistCurvesHpkeKem(new HkdfHpkeKdf("HmacSha384"), CurveType.NIST_P384);
      case NIST_P521:
        return new NistCurvesHpkeKem(new HkdfHpkeKdf("HmacSha512"), CurveType.NIST_P521);
    }
    throw new GeneralSecurityException("invalid curve type: " + curve);
  }

  private NistCurvesHpkeKem(HkdfHpkeKdf hkdf, CurveType curve) {
    this.hkdf = hkdf;
    this.curve = curve;
  }

  private byte[] deriveKemSharedSecret(
      byte[] dhSharedSecret, byte[] senderEphemeralPublicKey, byte[] recipientPublicKey)
      throws GeneralSecurityException {
    byte[] kemContext = Bytes.concat(senderEphemeralPublicKey, recipientPublicKey);
    return extractAndExpand(dhSharedSecret, kemContext);
  }

  private byte[] deriveKemSharedSecret(
      byte[] dhSharedSecret,
      byte[] senderEphemeralPublicKey,
      byte[] recipientPublicKey,
      byte[] senderPublicKey)
      throws GeneralSecurityException {
    byte[] kemContext = Bytes.concat(senderEphemeralPublicKey, recipientPublicKey, senderPublicKey);
    return extractAndExpand(dhSharedSecret, kemContext);
  }

  private byte[] extractAndExpand(byte[] dhSharedSecret, byte[] kemContext)
      throws GeneralSecurityException {
    byte[] kemSuiteID = HpkeUtil.kemSuiteId(getKemId());
    return hkdf.extractAndExpand(
        /* salt= */ null,
        dhSharedSecret,
        "eae_prk",
        kemContext,
        "shared_secret",
        kemSuiteID,
        hkdf.getMacLength());
  }

  /** Helper function factored out to facilitate unit testing. */
  HpkeKemEncapOutput encapsulate(byte[] recipientPublicKey, KeyPair senderEphemeralKeyPair)
      throws GeneralSecurityException {
    ECPublicKey recipientECPublicKey =
        EllipticCurves.getEcPublicKey(curve, PointFormatType.UNCOMPRESSED, recipientPublicKey);
    byte[] dhSharedSecret =
        EllipticCurves.computeSharedSecret(
            (ECPrivateKey) senderEphemeralKeyPair.getPrivate(), recipientECPublicKey);
    byte[] senderPublicKey =
        EllipticCurves.pointEncode(
            curve,
            PointFormatType.UNCOMPRESSED,
            ((ECPublicKey) senderEphemeralKeyPair.getPublic()).getW());
    byte[] kemSharedSecret =
        deriveKemSharedSecret(dhSharedSecret, senderPublicKey, recipientPublicKey);
    return new HpkeKemEncapOutput(kemSharedSecret, senderPublicKey);
  }

  @Override
  public HpkeKemEncapOutput encapsulate(byte[] recipientPublicKey) throws GeneralSecurityException {
    KeyPair keyPair = EllipticCurves.generateKeyPair(curve);
    return encapsulate(recipientPublicKey, keyPair);
  }

  /** Helper function factored out to facilitate unit testing. */
  HpkeKemEncapOutput authEncapsulate(
      byte[] recipientPublicKey, KeyPair senderEphemeralKeyPair, HpkeKemPrivateKey senderPrivateKey)
      throws GeneralSecurityException {
    ECPublicKey recipientECPublicKey =
        EllipticCurves.getEcPublicKey(curve, PointFormatType.UNCOMPRESSED, recipientPublicKey);
    ECPrivateKey privateKey =
        EllipticCurves.getEcPrivateKey(
            curve, senderPrivateKey.getSerializedPrivate().toByteArray());
    byte[] dhSharedSecret =
        Bytes.concat(
            EllipticCurves.computeSharedSecret(
                (ECPrivateKey) senderEphemeralKeyPair.getPrivate(), recipientECPublicKey),
            EllipticCurves.computeSharedSecret(privateKey, recipientECPublicKey));
    byte[] senderEphemeralPublicKey =
        EllipticCurves.pointEncode(
            curve,
            PointFormatType.UNCOMPRESSED,
            ((ECPublicKey) senderEphemeralKeyPair.getPublic()).getW());

    byte[] kemSharedSecret =
        deriveKemSharedSecret(
            dhSharedSecret,
            senderEphemeralPublicKey,
            recipientPublicKey,
            senderPrivateKey.getSerializedPublic().toByteArray());
    return new HpkeKemEncapOutput(kemSharedSecret, senderEphemeralPublicKey);
  }

  @Override
  public HpkeKemEncapOutput authEncapsulate(
      byte[] recipientPublicKey, HpkeKemPrivateKey senderPrivateKey)
      throws GeneralSecurityException {
    KeyPair keyPair = EllipticCurves.generateKeyPair(curve);
    return authEncapsulate(recipientPublicKey, keyPair, senderPrivateKey);
  }

  @Override
  public byte[] decapsulate(byte[] encapsulatedKey, HpkeKemPrivateKey recipientPrivateKey)
      throws GeneralSecurityException {
    ECPrivateKey privateKey =
        EllipticCurves.getEcPrivateKey(
            curve, recipientPrivateKey.getSerializedPrivate().toByteArray());
    ECPublicKey publicKey =
        EllipticCurves.getEcPublicKey(curve, PointFormatType.UNCOMPRESSED, encapsulatedKey);
    byte[] dhSharedSecret = EllipticCurves.computeSharedSecret(privateKey, publicKey);
    return deriveKemSharedSecret(
        dhSharedSecret, encapsulatedKey, recipientPrivateKey.getSerializedPublic().toByteArray());
  }

  @Override
  public byte[] authDecapsulate(
      byte[] encapsulatedKey, HpkeKemPrivateKey recipientPrivateKey, byte[] senderPublicKey)
      throws GeneralSecurityException {
    ECPrivateKey privateKey =
        EllipticCurves.getEcPrivateKey(
            curve, recipientPrivateKey.getSerializedPrivate().toByteArray());
    ECPublicKey senderEphemeralPublicKey =
        EllipticCurves.getEcPublicKey(curve, PointFormatType.UNCOMPRESSED, encapsulatedKey);

    byte[] dhSharedSecret =
        Bytes.concat(
            EllipticCurves.computeSharedSecret(privateKey, senderEphemeralPublicKey),
            EllipticCurves.computeSharedSecret(
                privateKey,
                EllipticCurves.getEcPublicKey(
                    curve, PointFormatType.UNCOMPRESSED, senderPublicKey)));
    return deriveKemSharedSecret(
        dhSharedSecret,
        encapsulatedKey,
        recipientPrivateKey.getSerializedPublic().toByteArray(),
        senderPublicKey);
  }

  @Override
  public byte[] getKemId() throws GeneralSecurityException {
    switch (curve) {
      case NIST_P256:
        return HpkeUtil.P256_HKDF_SHA256_KEM_ID;
      case NIST_P384:
        return HpkeUtil.P384_HKDF_SHA384_KEM_ID;
      case NIST_P521:
        return HpkeUtil.P521_HKDF_SHA512_KEM_ID;
    }
    throw new GeneralSecurityException("Could not determine HPKE KEM ID");
  }
}
