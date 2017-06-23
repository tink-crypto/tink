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

package com.google.crypto.tink.subtle;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.proto.EcPointFormat;
import com.google.crypto.tink.proto.HashType;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;

/**
 * ECIES encryption with HKDF-KEM (key encapsulation mechanism) and
 * AEAD-DEM (data encapsulation mechanism).
 */
public final class EciesAeadHkdfHybridEncrypt implements HybridEncrypt {
  private static final byte[] EMPTY_AAD = new byte[0];
  private final EciesHkdfSenderKem senderKem;
  private final String hkdfHmacAlgo;
  private final byte[] hkdfSalt;
  private final EcPointFormat ecPointFormat;
  private final EciesAeadHkdfDemHelper demHelper;

  public EciesAeadHkdfHybridEncrypt(final ECPublicKey recipientPublicKey,
      final byte[] hkdfSalt, HashType hkdfHashType, EcPointFormat ecPointFormat,
      EciesAeadHkdfDemHelper demHelper)
      throws GeneralSecurityException {
    EcUtil.checkPublicKey(recipientPublicKey);
    this.senderKem = new EciesHkdfSenderKem(recipientPublicKey);
    this.hkdfSalt = hkdfSalt;
    this.hkdfHmacAlgo = ProtoUtil.hashToHmacAlgorithmName(hkdfHashType);
    this.ecPointFormat = ecPointFormat;
    this.demHelper = demHelper;
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
        contextInfo, demHelper.getSymmetricKeySizeInBytes(), ecPointFormat);
    Aead aead = demHelper.getAead(kemKey.getSymmetricKey());
    byte[] ciphertext = aead.encrypt(plaintext, EMPTY_AAD);
    byte[] header = kemKey.getKemBytes();
    return ByteBuffer.allocate(header.length + ciphertext.length)
        .put(header)
        .put(ciphertext)
        .array();
  }
}
