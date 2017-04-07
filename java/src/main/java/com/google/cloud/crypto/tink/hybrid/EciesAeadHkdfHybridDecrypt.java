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
import com.google.cloud.crypto.tink.subtle.EciesHkdfRecipientKem;
import com.google.cloud.crypto.tink.subtle.HybridDecryptBase;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.EllipticCurve;
import java.util.Arrays;

/**
 * ECIES encryption with HKDF-KEM (key encapsulation mechanism) and
 * AEAD-DEM (data encapsulation mechanism).
 */
public final class EciesAeadHkdfHybridDecrypt extends HybridDecryptBase {
  private static final byte[] EMPTY_AAD = new byte[0];
  private final ECPrivateKey recipientPrivateKey;
  private final EciesHkdfRecipientKem recipientKem;
  private final byte[] hkdfSalt;
  private final String hkdfHmacAlgo;
  private final EcUtil.PointFormat ecPointFormat;
  private final EciesAeadHkdfAeadFactory aeadFactory;

  public EciesAeadHkdfHybridDecrypt(final ECPrivateKey recipientPrivateKey,
      final byte[] hkdfSalt, String hkdfHmacAlgo,
      KeyTemplate aeadDemTemplate, EcPointFormat ecPointFormat)
      throws GeneralSecurityException {
    this.recipientPrivateKey = recipientPrivateKey;
    this.recipientKem = new EciesHkdfRecipientKem(recipientPrivateKey);
    this.hkdfHmacAlgo = hkdfHmacAlgo;
    this.hkdfSalt = hkdfSalt;
    this.ecPointFormat = Util.getPointFormat(ecPointFormat);
    this.aeadFactory = new EciesAeadHkdfAeadFactory(aeadDemTemplate);  // validates the format
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] contextInfo)
      throws GeneralSecurityException {
    EllipticCurve curve = recipientPrivateKey.getParams().getCurve();
    int headerSize = EcUtil.encodingSizeInBytes(curve, ecPointFormat);
    if (ciphertext.length < headerSize) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    byte[] kem = Arrays.copyOfRange(ciphertext, 0, headerSize);
    byte[] symmetricKey = recipientKem.generateKey(
        kem, hkdfHmacAlgo, hkdfSalt, contextInfo, aeadFactory.getSymmetricKeySize(), ecPointFormat);
    Aead aead = aeadFactory.getAead(symmetricKey);
    return aead.decrypt(Arrays.copyOfRange(ciphertext, headerSize, ciphertext.length), EMPTY_AAD);
  }
}
