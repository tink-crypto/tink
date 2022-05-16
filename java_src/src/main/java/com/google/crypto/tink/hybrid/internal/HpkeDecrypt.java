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

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.proto.HpkeParams;
import com.google.crypto.tink.proto.HpkePrivateKey;
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

  private final HpkePrivateKey recipientPrivateKey;
  private final HpkeKem kem;
  private final HpkeKdf kdf;
  private final HpkeAead aead;
  private final int encapsulatedKeyLength;

  private HpkeDecrypt(
      HpkePrivateKey recipientPrivateKey,
      HpkeKem kem,
      HpkeKdf kdf,
      HpkeAead aead,
      int encapsulatedKeyLength) {
    this.recipientPrivateKey = recipientPrivateKey;
    this.kem = kem;
    this.kdf = kdf;
    this.aead = aead;
    this.encapsulatedKeyLength = encapsulatedKeyLength;
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
      default:
        throw new IllegalArgumentException(
            "Unable to determine KEM-encoding length for " + kemProtoEnum.name());
    }
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
    return new HpkeDecrypt(recipientPrivateKey, kem, kdf, aead, encapsulatedKeyLength);
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] contextInfo)
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
}
