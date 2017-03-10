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

package com.google.cloud.crypto.tink.hybrid; // instead of subtle, because it depends on KeyFormat.

import com.google.cloud.crypto.tink.Aead;
import com.google.cloud.crypto.tink.CommonProto.EcPointFormat;
import com.google.cloud.crypto.tink.EciesAeadHkdfProto.EciesAeadHkdfPayload;
import com.google.cloud.crypto.tink.TinkProto.KeyFormat;
import com.google.cloud.crypto.tink.subtle.EcUtil;
import com.google.cloud.crypto.tink.subtle.EciesHkdfSenderKem;
import com.google.cloud.crypto.tink.subtle.HybridEncryptBase;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

/**
 * ECIES encryption with HKDF-KEM (key encapsulation mechanism) and
 * AEAD-DEM (data encapsulation mechanism).
 */
public final class EciesAeadHkdfHybridEncrypt extends HybridEncryptBase {
  private static final byte[] EMPTY_AAD = new byte[0];
  private final ECPublicKey recipientPublicKey;
  private final EciesHkdfSenderKem senderKem;
  private final byte[] hkdfSalt;
  private final EcPointFormat ecPointFormat;
  private final EciesAeadHkdfAeadFactory aeadFactory;

  public EciesAeadHkdfHybridEncrypt(final ECPublicKey recipientPublicKey,
      final byte[] hkdfSalt, KeyFormat aeadDemFormat, EcPointFormat ecPointFormat)
      throws GeneralSecurityException {
    EcUtil.checkPublicKey(recipientPublicKey);
    this.recipientPublicKey = recipientPublicKey;
    this.senderKem = new EciesHkdfSenderKem(recipientPublicKey);
    this.hkdfSalt = hkdfSalt;
    if (ecPointFormat != EcPointFormat.UNCOMPRESSED) {
      throw new GeneralSecurityException("Unsupported EcPointFormat.");
    }
    this.ecPointFormat = ecPointFormat;
    this.aeadFactory = new EciesAeadHkdfAeadFactory(aeadDemFormat);  // validates the format
  }

  /**
   * Encrypts {@code plaintext} using {@code contextInfo} as <b>info</b>-parameter
   * of the underlying HKDF.
   *
   * @return resulting ciphertext.
   */
  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] contextInfo)
      throws GeneralSecurityException {
    EciesHkdfSenderKem.KemKey kemKey =
        senderKem.generateKey(aeadFactory.getSymmetricKeySize(), hkdfSalt, contextInfo);
    Aead aead = aeadFactory.getAead(kemKey.getSymmetricKey());
    byte[] ciphertext = aead.encrypt(plaintext, EMPTY_AAD);
    ECPoint pk = kemKey.getEphemeralPublicKey().getW();
    // TODO(przydatek): replace EciesAeadHkdfPayload-proto with a "manual" format.
    return EciesAeadHkdfPayload.newBuilder()
        .setEphemeralPkX(ByteString.copyFrom(pk.getAffineX().toByteArray()))
        .setEphemeralPkY(ByteString.copyFrom(pk.getAffineY().toByteArray()))
        .setCiphertext(ByteString.copyFrom(ciphertext))
        .build()
        .toByteArray();
  }
}
