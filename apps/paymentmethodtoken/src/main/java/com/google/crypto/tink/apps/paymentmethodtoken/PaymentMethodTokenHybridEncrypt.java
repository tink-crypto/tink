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

package com.google.crypto.tink.apps.paymentmethodtoken;

import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.EciesHkdfSenderKem;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * A {@link HybridEncrypt} implementation for the hybrid encryption used in <a
 * href="https://developers.google.com/android-pay/integration/payment-token-cryptography">Google
 * Payment Method Token</a>.
 */
class PaymentMethodTokenHybridEncrypt implements HybridEncrypt {
  private final EciesHkdfSenderKem senderKem;

  public PaymentMethodTokenHybridEncrypt(final ECPublicKey recipientPublicKey)
      throws GeneralSecurityException {
    this.senderKem = new EciesHkdfSenderKem(recipientPublicKey);
  }

  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] contextInfo)
      throws GeneralSecurityException {
    int symmetricKeySize =
        PaymentMethodTokenConstants.AES_CTR_KEY_SIZE
            + PaymentMethodTokenConstants.HMAC_SHA256_KEY_SIZE;
    EciesHkdfSenderKem.KemKey kemKey =
        senderKem.generateKey(
            PaymentMethodTokenConstants.HMAC_SHA256_ALGO,
            PaymentMethodTokenConstants.HKDF_EMPTY_SALT,
            contextInfo,
            symmetricKeySize,
            PaymentMethodTokenConstants.UNCOMPRESSED_POINT_FORMAT);
    byte[] aesCtrKey =
        Arrays.copyOfRange(
            kemKey.getSymmetricKey(), 0, PaymentMethodTokenConstants.AES_CTR_KEY_SIZE);
    byte[] ciphertext = PaymentMethodTokenUtil.aesCtr(aesCtrKey, plaintext);
    byte[] hmacSha256Key =
        Arrays.copyOfRange(
            kemKey.getSymmetricKey(),
            PaymentMethodTokenConstants.AES_CTR_KEY_SIZE,
            symmetricKeySize);
    byte[] tag = PaymentMethodTokenUtil.hmacSha256(hmacSha256Key, ciphertext);
    byte[] ephemeralPublicKey = kemKey.getKemBytes();
    try {
      return new JSONObject()
          .put(PaymentMethodTokenConstants.JSON_ENCRYPTED_MESSAGE_KEY, Base64.encode(ciphertext))
          .put(PaymentMethodTokenConstants.JSON_TAG_KEY, Base64.encode(tag))
          .put(
              PaymentMethodTokenConstants.JSON_EPHEMERAL_PUBLIC_KEY,
              Base64.encode(ephemeralPublicKey))
          .toString()
          .getBytes(StandardCharsets.UTF_8);
    } catch (JSONException e) {
      throw new GeneralSecurityException("cannot encrypt; JSON error");
    }
  }
}
