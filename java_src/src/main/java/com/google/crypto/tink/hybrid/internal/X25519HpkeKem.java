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

import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.X25519;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/** Diffie-Hellman-based X25519-HKDF HPKE KEM variant. */
@Immutable
final class X25519HpkeKem implements HpkeKem {
  private final HkdfHpkeKdf hkdf;

  /** Construct X25519-HKDF HPKE KEM using {@code hkdf}. */
  X25519HpkeKem(HkdfHpkeKdf hkdf) {
    this.hkdf = hkdf;
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
    byte[] kemSuiteId = HpkeUtil.kemSuiteId(HpkeUtil.X25519_HKDF_SHA256_KEM_ID);
    return hkdf.extractAndExpand(
        /* salt= */ null,
        dhSharedSecret,
        "eae_prk",
        kemContext,
        "shared_secret",
        kemSuiteId,
        hkdf.getMacLength());
  }

  /** Helper function factored out to facilitate unit testing. */
  HpkeKemEncapOutput encapsulate(byte[] recipientPublicKey, byte[] senderPrivateKey)
      throws GeneralSecurityException {
    byte[] dhSharedSecret = X25519.computeSharedSecret(senderPrivateKey, recipientPublicKey);
    byte[] senderPublicKey = X25519.publicFromPrivate(senderPrivateKey);
    byte[] kemSharedSecret =
        deriveKemSharedSecret(dhSharedSecret, senderPublicKey, recipientPublicKey);
    return new HpkeKemEncapOutput(kemSharedSecret, senderPublicKey);
  }

  @Override
  public HpkeKemEncapOutput encapsulate(byte[] recipientPublicKey) throws GeneralSecurityException {
    return encapsulate(recipientPublicKey, X25519.generatePrivateKey());
  }

  /** Helper function factored out to facilitate unit testing. */
  HpkeKemEncapOutput authEncapsulate(
      byte[] recipientPublicKey,
      byte[] senderEphemeralPrivateKey,
      HpkeKemPrivateKey senderPrivateKey)
      throws GeneralSecurityException {
    byte[] dhSharedSecret =
        Bytes.concat(
            X25519.computeSharedSecret(senderEphemeralPrivateKey, recipientPublicKey),
            X25519.computeSharedSecret(
                senderPrivateKey.getSerializedPrivate().toByteArray(), recipientPublicKey));
    byte[] senderEphemeralPublicKey = X25519.publicFromPrivate(senderEphemeralPrivateKey);
    byte[] senderPublicKey =
        X25519.publicFromPrivate(senderPrivateKey.getSerializedPrivate().toByteArray());
    byte[] kemSharedSecret =
        deriveKemSharedSecret(
            dhSharedSecret, senderEphemeralPublicKey, recipientPublicKey, senderPublicKey);
    return new HpkeKemEncapOutput(kemSharedSecret, senderEphemeralPublicKey);
  }

  @Override
  public HpkeKemEncapOutput authEncapsulate(
      byte[] recipientPublicKey, HpkeKemPrivateKey senderPrivateKey)
      throws GeneralSecurityException {
    return authEncapsulate(recipientPublicKey, X25519.generatePrivateKey(), senderPrivateKey);
  }

  @Override
  public byte[] decapsulate(byte[] encapsulatedKey, HpkeKemPrivateKey recipientPrivateKey)
      throws GeneralSecurityException {
    byte[] dhSharedSecret =
        X25519.computeSharedSecret(
            recipientPrivateKey.getSerializedPrivate().toByteArray(), encapsulatedKey);
    return deriveKemSharedSecret(
        dhSharedSecret, encapsulatedKey, recipientPrivateKey.getSerializedPublic().toByteArray());
  }

  @Override
  public byte[] authDecapsulate(
      byte[] encapsulatedKey, HpkeKemPrivateKey recipientPrivateKey, byte[] senderPublicKey)
      throws GeneralSecurityException {
    byte[] privateKey = recipientPrivateKey.getSerializedPrivate().toByteArray();
    byte[] dhSharedSecret =
        Bytes.concat(
            X25519.computeSharedSecret(privateKey, encapsulatedKey),
            X25519.computeSharedSecret(privateKey, senderPublicKey));
    byte[] recipientPublicKey = X25519.publicFromPrivate(privateKey);
    return deriveKemSharedSecret(
        dhSharedSecret, encapsulatedKey, recipientPublicKey, senderPublicKey);
  }

  @Override
  public byte[] getKemId() throws GeneralSecurityException {
    if (Arrays.equals(hkdf.getKdfId(), HpkeUtil.HKDF_SHA256_KDF_ID)) {
      return HpkeUtil.X25519_HKDF_SHA256_KEM_ID;
    }
    throw new GeneralSecurityException("Could not determine HPKE KEM ID");
  }
}
