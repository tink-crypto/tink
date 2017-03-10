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

package com.google.cloud.crypto.tink.subtle;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import javax.crypto.KeyAgreement;

/**
 * HKDF-based KEM (key encapsulation mechanism) for ECIES recipient.
 */
public final class EciesHkdfRecipientKem {
  private ECPrivateKey recipientPrivateKey;

  public EciesHkdfRecipientKem(final ECPrivateKey recipientPrivateKey) {
    this.recipientPrivateKey = recipientPrivateKey;
  }

  public byte[] generateKey(final ECPoint ephemeralPublicPoint, int keySizeInBytes,
      String hmacAlgo, final byte[] hkdfSalt, final byte[] hkdfInfo)
      throws GeneralSecurityException {
    ECParameterSpec spec = recipientPrivateKey.getParams();
    ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ephemeralPublicPoint, spec);
    KeyFactory kf = KeyFactory.getInstance("EC");
    ECPublicKey ephemeralPublicKey = (ECPublicKey) kf.generatePublic(publicKeySpec);
    byte[] sharedSecret = getSharedSecret(ephemeralPublicKey);
    return Hkdf.computeEciesHkdfSymmetricKey(ephemeralPublicKey,
        sharedSecret, keySizeInBytes, hmacAlgo, hkdfSalt, hkdfInfo);
  }

  private byte[] getSharedSecret(final ECPublicKey publicKey)
      throws GeneralSecurityException {
    ECParameterSpec spec = recipientPrivateKey.getParams();
    EcUtil.checkPointOnCurve(publicKey.getW(), spec.getCurve());
    KeyAgreement ka = KeyAgreement.getInstance("ECDH");
    ka.init(recipientPrivateKey);
    ka.doPhase(publicKey, true);
    return ka.generateSecret();
  }
}
