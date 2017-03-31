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

package com.google.cloud.crypto.tink.hybrid; // instead of subtle, because it depends on KeyTemplate.

import com.google.cloud.crypto.tink.Aead;
import com.google.cloud.crypto.tink.CommonProto.EcPointFormat;
import com.google.cloud.crypto.tink.TinkProto.KeyTemplate;
import com.google.cloud.crypto.tink.Util;
import com.google.cloud.crypto.tink.subtle.EcUtil;
import com.google.cloud.crypto.tink.subtle.EciesHkdfSenderKem;
import com.google.cloud.crypto.tink.subtle.HybridEncryptBase;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;

/**
 * ECIES encryption with HKDF-KEM (key encapsulation mechanism) and
 * AEAD-DEM (data encapsulation mechanism).
 */
public final class EciesAeadHkdfHybridEncrypt extends HybridEncryptBase {
  private static final byte[] EMPTY_AAD = new byte[0];
  private final ECPublicKey recipientPublicKey;
  private final EciesHkdfSenderKem senderKem;
  private final String hkdfHmacAlgo;
  private final byte[] hkdfSalt;
  private final EcUtil.PointFormat ecPointFormat;
  private final EciesAeadHkdfAeadFactory aeadFactory;

  public EciesAeadHkdfHybridEncrypt(final ECPublicKey recipientPublicKey,
      final byte[] hkdfSalt, String hkdfHmacAlgo,
      KeyTemplate aeadDemTemplate, EcPointFormat ecPointFormat)
      throws GeneralSecurityException {
    EcUtil.checkPublicKey(recipientPublicKey);
    this.recipientPublicKey = recipientPublicKey;
    this.senderKem = new EciesHkdfSenderKem(recipientPublicKey);
    this.hkdfSalt = hkdfSalt;
    this.hkdfHmacAlgo = hkdfHmacAlgo;
    this.ecPointFormat = Util.getPointFormat(ecPointFormat);
    this.aeadFactory = new EciesAeadHkdfAeadFactory(aeadDemTemplate);  // validates the format
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
    EciesHkdfSenderKem.KemKey kemKey =  senderKem.generateKey(hkdfHmacAlgo, hkdfSalt,
        contextInfo, aeadFactory.getSymmetricKeySize(), ecPointFormat);
    Aead aead = aeadFactory.getAead(kemKey.getSymmetricKey());
    byte[] ciphertext = aead.encrypt(plaintext, EMPTY_AAD);
    byte[] header = kemKey.getKemBytes();
    return ByteBuffer.allocate(header.length + ciphertext.length)
        .put(header)
        .put(ciphertext)
        .array();
  }
}
