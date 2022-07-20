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

import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.proto.HpkeParams;
import com.google.crypto.tink.proto.HpkePublicKey;
import com.google.crypto.tink.subtle.Bytes;
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

  private final HpkePublicKey recipientPublicKey;
  private final HpkeKem kem;
  private final HpkeKdf kdf;
  private final HpkeAead aead;

  private HpkeEncrypt(HpkePublicKey recipientPublicKey, HpkeKem kem, HpkeKdf kdf, HpkeAead aead) {
    this.recipientPublicKey = recipientPublicKey;
    this.kem = kem;
    this.kdf = kdf;
    this.aead = aead;
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
    return new HpkeEncrypt(recipientPublicKey, kem, kdf, aead);
  }

  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] contextInfo)
      throws GeneralSecurityException {
    byte[] info = contextInfo;
    if (info == null) {
      info = new byte[0];
    }
    HpkeContext context = HpkeContext.createSenderContext(recipientPublicKey, kem, kdf, aead, info);
    byte[] ciphertext = context.seal(plaintext, EMPTY_ASSOCIATED_DATA);
    return Bytes.concat(context.getEncapsulatedKey(), ciphertext);
  }
}
