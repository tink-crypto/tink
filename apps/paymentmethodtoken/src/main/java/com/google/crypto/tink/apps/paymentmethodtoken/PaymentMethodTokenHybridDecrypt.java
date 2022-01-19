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

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.apps.paymentmethodtoken.PaymentMethodTokenConstants.ProtocolVersionConfig;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.Hkdf;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

/**
 * A {@link HybridDecrypt} implementation for the hybrid encryption used in <a
 * href="https://developers.google.com/pay/api/payment-data-cryptography">Google Payment Method
 * Token</a>.
 */
class PaymentMethodTokenHybridDecrypt implements HybridDecrypt {
  private final PaymentMethodTokenRecipientKem recipientKem;
  private final ProtocolVersionConfig protocolVersionConfig;

  PaymentMethodTokenHybridDecrypt(
      final ECPrivateKey recipientPrivateKey, ProtocolVersionConfig protocolVersionConfig)
      throws GeneralSecurityException {
    this(
        new PaymentMethodTokenRecipientKem() {
          @Override
          public byte[] computeSharedSecret(final byte[] ephemeralPublicKey)
              throws GeneralSecurityException {
            ECPublicKey publicKey =
                EllipticCurves.getEcPublicKey(
                    recipientPrivateKey.getParams(),
                    PaymentMethodTokenConstants.UNCOMPRESSED_POINT_FORMAT,
                    ephemeralPublicKey);
            return EllipticCurves.computeSharedSecret(recipientPrivateKey, publicKey);
          }
        },
        protocolVersionConfig);
  }

  PaymentMethodTokenHybridDecrypt(
      final PaymentMethodTokenRecipientKem recipientKem,
      ProtocolVersionConfig protocolVersionConfig) {
    this.recipientKem = recipientKem;
    this.protocolVersionConfig = protocolVersionConfig;
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] contextInfo)
      throws GeneralSecurityException {
    try {
      JsonObject json = JsonParser.parseString(new String(ciphertext, UTF_8)).getAsJsonObject();
      validate(json);
      byte[] demKey = kem(json, contextInfo);
      return dem(json, demKey);
    } catch (JsonParseException | IllegalStateException e) {
      throw new GeneralSecurityException("cannot decrypt; failed to parse JSON", e);
    }
  }

  private byte[] kem(JsonObject json, final byte[] contextInfo) throws GeneralSecurityException {
    int demKeySize = protocolVersionConfig.aesCtrKeySize + protocolVersionConfig.hmacSha256KeySize;
    byte[] ephemeralPublicKey =
        Base64.decode(
            json.get(PaymentMethodTokenConstants.JSON_EPHEMERAL_PUBLIC_KEY).getAsString());
    byte[] sharedSecret = recipientKem.computeSharedSecret(ephemeralPublicKey);
    return Hkdf.computeEciesHkdfSymmetricKey(
        ephemeralPublicKey,
        sharedSecret,
        PaymentMethodTokenConstants.HMAC_SHA256_ALGO,
        PaymentMethodTokenConstants.HKDF_EMPTY_SALT,
        contextInfo,
        demKeySize);
  }

  private byte[] dem(JsonObject json, final byte[] demKey) throws GeneralSecurityException {
    byte[] hmacSha256Key =
        Arrays.copyOfRange(demKey, protocolVersionConfig.aesCtrKeySize, demKey.length);
    byte[] encryptedMessage =
        Base64.decode(
            json.get(PaymentMethodTokenConstants.JSON_ENCRYPTED_MESSAGE_KEY).getAsString());
    byte[] computedTag = PaymentMethodTokenUtil.hmacSha256(hmacSha256Key, encryptedMessage);
    byte[] expectedTag =
        Base64.decode(json.get(PaymentMethodTokenConstants.JSON_TAG_KEY).getAsString());
    if (!Bytes.equal(expectedTag, computedTag)) {
      throw new GeneralSecurityException("cannot decrypt; invalid MAC");
    }
    byte[] aesCtrKey = Arrays.copyOf(demKey, protocolVersionConfig.aesCtrKeySize);
    return PaymentMethodTokenUtil.aesCtr(aesCtrKey, encryptedMessage);
  }

  private void validate(JsonObject payload) throws GeneralSecurityException {
    if (!payload.has(PaymentMethodTokenConstants.JSON_ENCRYPTED_MESSAGE_KEY)
        || !payload.has(PaymentMethodTokenConstants.JSON_TAG_KEY)
        || !payload.has(PaymentMethodTokenConstants.JSON_EPHEMERAL_PUBLIC_KEY)
        || payload.size() != 3) {
      throw new GeneralSecurityException(
          "The payload must contain exactly encryptedMessage, tag and ephemeralPublicKey");
    }
  }
}
