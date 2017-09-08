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
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.EcdsaSignJce;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * An implementation of the sender side of <a
 * href="https://developers.google.com/android-pay/integration/payment-token-cryptography">Google
 * Payment Method Token</a>.
 *
 * <p><b>Warning</b> This implementation supports only version {@code ECv1}.
 *
 * <p>Usage:
 *
 * <pre>{@code
 * PaymentMethodTokenSender sender = new PaymentMethodTokenSender.Builder()
 *    .senderId(senderId)
 *    .senderSigningKey(senderPrivateKey)
 *    .recipientId(recipientId)
 *    .recipientPublicKey(recipientPublicKey)
 *    .build();
 * String plaintext = "blah";
 * String ciphertext = sender.seal(plaintext);
 * }</pre>
 */
public final class PaymentMethodTokenSender {
  private final String protocolVersion;
  private final PublicKeySign signer;
  private final HybridEncrypt hybridEncrypter;
  private final String senderId;
  private final String recipientId;

  PaymentMethodTokenSender(
      final String protocolVersion,
      final ECPrivateKey senderSigningKey,
      String senderId,
      final ECPublicKey recipientPublicKey,
      String recipientId)
      throws GeneralSecurityException {
    if (!protocolVersion.equals(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V1)) {
      throw new IllegalArgumentException("invalid version: " + protocolVersion);
    }
    this.protocolVersion = protocolVersion;
    if (senderSigningKey == null) {
      throw new IllegalArgumentException(
          "must set sender's signing key using Builder.senderSigningKey");
    }
    this.signer =
        new EcdsaSignJce(senderSigningKey, PaymentMethodTokenConstants.ECDSA_SHA256_SIGNING_ALGO);
    this.senderId = senderId;
    if (recipientPublicKey == null) {
      throw new IllegalArgumentException(
          "must set recipient's public key using Builder.recipientPublicKey");
    }
    this.hybridEncrypter = new PaymentMethodTokenHybridEncrypt(recipientPublicKey);
    if (recipientId == null) {
      throw new IllegalArgumentException("must set recipient Id using Builder.recipientId");
    }
    this.recipientId = recipientId;
  }

  private PaymentMethodTokenSender(Builder builder) throws GeneralSecurityException {
    this(
        builder.protocolVersion,
        builder.senderSigningKey,
        builder.senderId,
        builder.recipientPublicKey,
        builder.recipientId);
  }

  /** Builder for PaymentMethodTokenSender. */
  public static class Builder {
    private String protocolVersion = PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V1;
    private String senderId = PaymentMethodTokenConstants.GOOGLE_SENDER_ID;
    private String recipientId = null;
    private ECPrivateKey senderSigningKey = null;
    private ECPublicKey recipientPublicKey = null;

    public Builder() {}

    /** Sets the protocolVersion. */
    public Builder protocolVersion(String val) {
      protocolVersion = val;
      return this;
    }

    /** Sets the sender Id. */
    public Builder senderId(String val) {
      senderId = val;
      return this;
    }

    /** Sets the recipient Id. */
    public Builder recipientId(String val) {
      recipientId = val;
      return this;
    }

    /**
     * Sets the signing key of the sender.
     *
     * <p>It must be base64 encoded PKCS8 private key.
     */
    public Builder senderSigningKey(String val) throws GeneralSecurityException {
      senderSigningKey = PaymentMethodTokenUtil.pkcs8EcPrivateKey(val);
      return this;
    }

    public Builder senderSigningKey(ECPrivateKey val) throws GeneralSecurityException {
      senderSigningKey = val;
      return this;
    }

    /**
     * Sets the encryption public key of the recipient.
     *
     * <p>The public key is a base64 (no wrapping, padded) version of the key encoded in ASN.1 type
     * SubjectPublicKeyInfo defined in the X.509 standard.
     */
    public Builder recipientPublicKey(String val) throws GeneralSecurityException {
      recipientPublicKey = PaymentMethodTokenUtil.x509EcPublicKey(val);
      return this;
    }

    /**
     * Sets the encryption public key of the recipient.
     *
     * <p>The public key must be formatted as base64 encoded uncompressed point format. This format
     * is described in more detail in "Public Key Cryptography For The Financial Services Industry:
     * The Elliptic Curve Digital Signature Algorithm (ECDSA)", ANSI X9.62, 1998
     */
    public Builder rawUncompressedRecipientPublicKey(String val) throws GeneralSecurityException {
      recipientPublicKey = PaymentMethodTokenUtil.rawUncompressedEcPublicKey(val);
      return this;
    }

    public Builder recipientPublicKey(ECPublicKey val) throws GeneralSecurityException {
      recipientPublicKey = val;
      return this;
    }

    public PaymentMethodTokenSender build() throws GeneralSecurityException {
      return new PaymentMethodTokenSender(this);
    }
  }

  /** Seals the input message according to the Payment Method Token specification. */
  public String seal(final String message) throws GeneralSecurityException {
    if (protocolVersion.equals(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V1)) {
      return sealv1(message);
    }
    throw new GeneralSecurityException("Unsupported version: " + protocolVersion);
  }

  private String sealv1(final String message) throws GeneralSecurityException {
    String signedMessage =
        new String(
            hybridEncrypter.encrypt(
                message.getBytes(StandardCharsets.UTF_8),
                PaymentMethodTokenConstants.GOOGLE_CONTEXT_INFO_ECV1),
            StandardCharsets.UTF_8);
    byte[] toSignBytes =
        PaymentMethodTokenUtil.toLengthValue(
            // The order of the parameters matters.
            senderId,
            recipientId,
            PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V1,
            signedMessage);
    byte[] signature = signer.sign(toSignBytes);
    try {
      return new JSONObject()
          .put(PaymentMethodTokenConstants.JSON_SIGNED_MESSAGE_KEY, signedMessage)
          .put(
              PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY,
              PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V1)
          .put(PaymentMethodTokenConstants.JSON_SIGNATURE_KEY, Base64.encode(signature))
          .toString();
    } catch (JSONException e) {
      throw new GeneralSecurityException("cannot seal; JSON error");
    }
  }
}
