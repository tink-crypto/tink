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

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.EciesHkdfRecipientKem;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPrivateKey;
import java.util.Arrays;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * A {@link HybridDecrypt} implementation for the hybrid encryption used in <a
 * href="https://developers.google.com/android-pay/integration/payment-token-cryptography">Google
 * Payment Method Token</a>.
 */
class PaymentMethodTokenHybridDecrypt implements HybridDecrypt {
  private final EciesHkdfRecipientKem recipientKem;

  public PaymentMethodTokenHybridDecrypt(final ECPrivateKey recipientPrivateKey)
      throws GeneralSecurityException {
    this.recipientKem = new EciesHkdfRecipientKem(recipientPrivateKey);
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] contextInfo)
      throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(ciphertext, StandardCharsets.UTF_8));
      validate(json);
      byte[] kem =
          Base64.decode(json.getString(PaymentMethodTokenConstants.JSON_EPHEMERAL_PUBLIC_KEY));
      int symmetricKeySize =
          PaymentMethodTokenConstants.AES_CTR_KEY_SIZE
              + PaymentMethodTokenConstants.HMAC_SHA256_KEY_SIZE;
      byte[] demKey =
          recipientKem.generateKey(
              kem,
              PaymentMethodTokenConstants.HMAC_SHA256_ALGO,
              PaymentMethodTokenConstants.HKDF_EMPTY_SALT,
              contextInfo,
              symmetricKeySize,
              PaymentMethodTokenConstants.UNCOMPRESSED_POINT_FORMAT);
      byte[] hmacSha256Key =
          Arrays.copyOfRange(
              demKey, PaymentMethodTokenConstants.AES_CTR_KEY_SIZE, symmetricKeySize);
      byte[] encryptedMessage =
          Base64.decode(json.getString(PaymentMethodTokenConstants.JSON_ENCRYPTED_MESSAGE_KEY));
      byte[] computedTag = PaymentMethodTokenUtil.hmacSha256(hmacSha256Key, encryptedMessage);
      byte[] expectedTag = Base64.decode(json.getString(PaymentMethodTokenConstants.JSON_TAG_KEY));
      if (!Bytes.equal(expectedTag, computedTag)) {
        throw new GeneralSecurityException("cannot decrypt; invalid MAC");
      }
      byte[] aesCtrKey =
          Arrays.copyOfRange(demKey, 0, PaymentMethodTokenConstants.AES_CTR_KEY_SIZE);
      return PaymentMethodTokenUtil.aesCtr(aesCtrKey, encryptedMessage);
    } catch (JSONException e) {
      throw new GeneralSecurityException("cannot decrypt; failed to parse JSON");
    }
  }

  private void validate(final JSONObject payload) throws GeneralSecurityException {
    if (!payload.has(PaymentMethodTokenConstants.JSON_ENCRYPTED_MESSAGE_KEY)
        || !payload.has(PaymentMethodTokenConstants.JSON_TAG_KEY)
        || !payload.has(PaymentMethodTokenConstants.JSON_EPHEMERAL_PUBLIC_KEY)
        || payload.length() != 3) {
      throw new GeneralSecurityException(
          "The payload must contain exactly encryptedMessage, tag and ephemeralPublicKey");
    }
  }
}
