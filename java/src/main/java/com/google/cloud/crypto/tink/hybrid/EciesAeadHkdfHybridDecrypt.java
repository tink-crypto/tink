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
import com.google.cloud.crypto.tink.subtle.EciesHkdfRecipientKem;
import com.google.cloud.crypto.tink.subtle.HybridDecryptBase;
import com.google.protobuf.InvalidProtocolBufferException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECPoint;

/**
 * ECIES encryption with HKDF-KEM (key encapsulation mechanism) and
 * AEAD-DEM (data encapsulation mechanism).
 */
public final class EciesAeadHkdfHybridDecrypt extends HybridDecryptBase {
  private static final byte[] EMPTY_AAD = new byte[0];
  private final ECPrivateKey recipientPrivateKey;
  private final EciesHkdfRecipientKem recipientKem;
  private final byte[] hkdfSalt;
  private final EcPointFormat ecPointFormat;
  private final EciesAeadHkdfAeadFactory aeadFactory;

  public EciesAeadHkdfHybridDecrypt(final ECPrivateKey recipientPrivateKey,
      final byte[] hkdfSalt, KeyFormat aeadDemFormat, EcPointFormat ecPointFormat)
      throws GeneralSecurityException {
    this.recipientPrivateKey = recipientPrivateKey;
    this.recipientKem = new EciesHkdfRecipientKem(recipientPrivateKey);
    this.hkdfSalt = hkdfSalt;
    if (ecPointFormat != EcPointFormat.UNCOMPRESSED) {
      throw new GeneralSecurityException("Unsupported EcPointFormat.");
    }
    this.ecPointFormat = ecPointFormat;
    this.aeadFactory = new EciesAeadHkdfAeadFactory(aeadDemFormat);  // validates the format
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] contextInfo)
      throws GeneralSecurityException {
    try {
      EciesAeadHkdfPayload payload = EciesAeadHkdfPayload.parseFrom(ciphertext);
      ECPoint ephemeralPublicPoint = new ECPoint(
          new BigInteger(1, payload.getEphemeralPkX().toByteArray()),
          new BigInteger(1, payload.getEphemeralPkY().toByteArray()));

      byte[] symmetricKey = recipientKem.generateKey(
          ephemeralPublicPoint, aeadFactory.getSymmetricKeySize(), hkdfSalt, contextInfo);
      Aead aead = aeadFactory.getAead(symmetricKey);
      return aead.decrypt(payload.getCiphertext().toByteArray(), EMPTY_AAD);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Invalid KeyFormat protobuf, expected AesGcmKeyFormat.");
    }
  }

  private void validate(KeyFormat demFormat) throws GeneralSecurityException {
    if (!demFormat.getKeyType().equals("type.googleapis.com/google.cloud.crypto.tink.AesGcmKey")) {
      throw new GeneralSecurityException("Expected AesGcmKey as AEAD-DEM Key.");
    }
  }

}
