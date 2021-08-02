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

import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.apps.paymentmethodtoken.PaymentMethodTokenConstants.ProtocolVersionConfig;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.EcdsaSignJce;
import com.google.crypto.tink.subtle.EllipticCurves.EcdsaEncoding;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.gson.internal.Streams;
import com.google.gson.stream.JsonWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

/**
 * An implementation of the sender side of <a
 * href="https://developers.google.com/pay/api/payment-data-cryptography">Google Payment Method
 * Token</a>.
 *
 * <h3>Warning</h3>
 *
 * <p>This implementation supports only versions {@code ECv1} and {@code ECv2}.
 *
 * <h3>Usage</h3>
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
 *
 * @see <a href="https://developers.google.com/pay/api/payment-data-cryptography">Google Payment
 *     Method Token standard</a>
 * @since 1.0.0
 */
public final class PaymentMethodTokenSender {
  private final String protocolVersion;
  private final ProtocolVersionConfig protocolVersionConfig;
  private final PublicKeySign signer;
  private final String senderIntermediateCert;
  private final String senderId;
  private final String recipientId;
  private final byte[] contextInfo;

  private HybridEncrypt hybridEncrypter;

  PaymentMethodTokenSender(Builder builder) throws GeneralSecurityException {
    switch (builder.protocolVersion) {
      case PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V1:
        validateV1(builder);
        break;
      case PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2:
        validateV2(builder);
        break;
      case PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY:
        validateV2SigningOnly(builder);
        break;
      default:
        throw new IllegalArgumentException("invalid version: " + builder.protocolVersion);
    }

    this.protocolVersion = builder.protocolVersion;
    this.protocolVersionConfig = ProtocolVersionConfig.forProtocolVersion(protocolVersion);
    this.signer =
        new EcdsaSignJce(
            builder.senderIntermediateSigningKey != null
                ? builder.senderIntermediateSigningKey
                : builder.senderSigningKey,
            PaymentMethodTokenConstants.ECDSA_HASH_SHA256,
            EcdsaEncoding.DER);
    this.senderId = builder.senderId;
    if (protocolVersionConfig.isEncryptionRequired) {
      this.hybridEncrypter =
          new PaymentMethodTokenHybridEncrypt(builder.recipientPublicKey, protocolVersionConfig);
    }
    if (builder.recipientId == null) {
      throw new IllegalArgumentException("must set recipient Id using Builder.recipientId");
    }
    this.recipientId = builder.recipientId;
    this.senderIntermediateCert = builder.senderIntermediateCert;
    this.contextInfo = builder.contextInfo;
  }

  /**
   * Builder for {@link PaymentMethodTokenSender}.
   *
   * @since 1.0.0
   */
  public static class Builder {
    private String protocolVersion = PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V1;
    private String senderId = PaymentMethodTokenConstants.GOOGLE_SENDER_ID;
    private String recipientId = null;
    private ECPrivateKey senderSigningKey = null;
    private ECPrivateKey senderIntermediateSigningKey = null;
    private String senderIntermediateCert = null;
    private ECPublicKey recipientPublicKey = null;
    private byte[] contextInfo = PaymentMethodTokenConstants.GOOGLE_CONTEXT_INFO_ECV1;

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

    public Builder contextInfo(String val) {
      contextInfo = val.getBytes(UTF_8);
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
     * Sets the intermediate signing key of the sender.
     *
     * <p>It must be base64 encoded PKCS8 private key.
     *
     * @since 1.1.0
     */
    public Builder senderIntermediateSigningKey(String val) throws GeneralSecurityException {
      return senderIntermediateSigningKey(PaymentMethodTokenUtil.pkcs8EcPrivateKey(val));
    }

    /**
     * Sets the intermediate signing key of the sender.
     *
     * @since 1.1.0
     */
    public Builder senderIntermediateSigningKey(ECPrivateKey val) throws GeneralSecurityException {
      senderIntermediateSigningKey = val;
      return this;
    }

    /**
     * JSON containing sender intermediate signing key and a signature of it by the sender signing
     * key.
     *
     * <p>This can be generated by {@link SenderIntermediateCertFactory}.
     *
     * @since 1.1.0
     */
    public Builder senderIntermediateCert(String val) throws GeneralSecurityException {
      this.senderIntermediateCert = val;
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
    if (protocolVersion.equals(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V1)
        || protocolVersion.equals(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
        || protocolVersion.equals(
            PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)) {
      return sealV1OrV2(message);
    }
    throw new GeneralSecurityException("Unsupported version: " + protocolVersion);
  }

  private String sealV1OrV2(final String message) throws GeneralSecurityException {
    String signedMessage =
        protocolVersionConfig.isEncryptionRequired
            ? new String(
                hybridEncrypter.encrypt(message.getBytes(UTF_8), contextInfo),
                UTF_8)
            : message;
    return signV1OrV2(signedMessage);
  }

  static String jsonEncodeSignedMessage(
      String message, String protocolVersion, byte[] signature, String senderIntermediateCert)
      throws GeneralSecurityException {
    try {
      JsonObject result = new JsonObject();
      result.addProperty(PaymentMethodTokenConstants.JSON_SIGNATURE_KEY, Base64.encode(signature));
      if (senderIntermediateCert != null) {
        result.add(
            PaymentMethodTokenConstants.JSON_INTERMEDIATE_SIGNING_KEY,
            JsonParser.parseString(senderIntermediateCert).getAsJsonObject());
      }
      result.addProperty(PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY, protocolVersion);
      result.addProperty(PaymentMethodTokenConstants.JSON_SIGNED_MESSAGE_KEY, message);
      StringWriter stringWriter = new StringWriter();
      JsonWriter jsonWriter = new JsonWriter(stringWriter);
      jsonWriter.setHtmlSafe(true);
      Streams.write(result, jsonWriter);
      return stringWriter.toString();
    } catch (JsonParseException | IllegalStateException | IOException e) {
      throw new GeneralSecurityException("cannot seal; JSON error", e);
    }
  }

  private String signV1OrV2(String message) throws GeneralSecurityException {
    byte[] toSignBytes =
        PaymentMethodTokenUtil.toLengthValue(
            // The order of the parameters matters.
            senderId, recipientId, protocolVersion, message);
    byte[] signature = signer.sign(toSignBytes);
    return jsonEncodeSignedMessage(message, protocolVersion, signature, senderIntermediateCert);
  }

  private static void validateV1(Builder builder) {
    // ECv1 signed payloads directly.
    if (builder.senderSigningKey == null) {
      throw new IllegalArgumentException(
          "must set sender's signing key using Builder.senderSigningKey");
    }
    if (builder.senderIntermediateSigningKey != null) {
      throw new IllegalArgumentException(
          "must not set sender's intermediate signing key using "
              + "Builder.senderIntermediateSigningKey");
    }
    if (builder.senderIntermediateCert != null) {
      throw new IllegalArgumentException(
          "must not set signed sender's intermediate signing key using "
              + "Builder.senderIntermediateCert");
    }
    if (builder.recipientPublicKey == null) {
      throw new IllegalArgumentException(
          "must set recipient's public key using Builder.recipientPublicKey");
    }
  }

  private static void validateV2(Builder builder) {
    validateIntermediateSigningKeys(builder);
    if (builder.recipientPublicKey == null) {
      throw new IllegalArgumentException(
          "must set recipient's public key using Builder.recipientPublicKey");
    }
  }

  private static void validateV2SigningOnly(Builder builder) {
    validateIntermediateSigningKeys(builder);
    if (builder.recipientPublicKey != null) {
      throw new IllegalArgumentException(
          "must not set recipient's public key using Builder.recipientPublicKey");
    }
  }

  private static void validateIntermediateSigningKeys(Builder builder) {
    // ECv2 and newer protocols use an intermediate signing key.
    if (builder.senderSigningKey != null) {
      throw new IllegalArgumentException(
          "must not set sender's signing key using Builder.senderSigningKey");
    }
    if (builder.senderIntermediateSigningKey == null) {
      throw new IllegalArgumentException(
          "must set sender's intermediate signing key using "
              + "Builder.senderIntermediateSigningKey");
    }
    if (builder.senderIntermediateCert == null) {
      throw new IllegalArgumentException(
          "must set signed sender's intermediate signing key using "
              + "Builder.senderIntermediateCert");
    }
  }
}
