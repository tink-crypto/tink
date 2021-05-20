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
import com.google.crypto.tink.subtle.EcdsaVerifyJce;
import com.google.crypto.tink.subtle.EllipticCurves.EcdsaEncoding;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.joda.time.Instant;

/**
 * An implementation of the recipient side of <a
 * href="https://developers.google.com/pay/api/payment-data-cryptography">Google Payment Method
 * Token</a>.
 *
 * <h3>Warning</h3>
 *
 * <p>This implementation only supports versions {@code ECv1}, {@code ECv2} and {@code
 * ECv2SigningOnly}.
 *
 * <h3>Typical usage</h3>
 *
 * <pre>{@code
 * PaymentMethodTokenRecipient recipient = new PaymentMethodTokenRecipient.Builder()
 *     .fetchSenderVerifyingKeysWith(
 *         GooglePaymentsPublicKeysManager.INSTANCE_PRODUCTION)
 *     .recipientId(recipientId)
 *     // Multiple recipient private keys can be added to support graceful key rotations
 *     .addRecipientPrivateKey(recipientPrivateKey1)
 *     .addRecipientPrivateKey(recipientPrivateKey2)
 *     .build();
 * String ciphertext = ...;
 * String plaintext = recipient.unseal(ciphertext);
 * }</pre>
 *
 * <h3>Custom decryption</h3>
 *
 * <p>Recipients that store private keys in HSM can provide implementations of {@link
 * PaymentMethodTokenRecipientKem} and configure Tink to use their custom code with {@link
 * PaymentMethodTokenRecipient.Builder#addRecipientKem}.
 *
 * <pre>{@code
 * PaymentMethodTokenRecipient recipient = new PaymentMethodTokenRecipient.Builder()
 *     .fetchSenderVerifyingKeysWith(
 *         GooglePaymentsPublicKeysManager.INSTANCE_PRODUCTION)
 *     .recipientId(recipientId)
 *     .addRecipientKem(new MyPaymentMethodTokenRecipientKem())
 *     .build();
 * String ciphertext = ...;
 * String plaintext = recipient.unseal(ciphertext);
 * }</pre>
 *
 * @see <a href="https://developers.google.com/pay/api/payment-data-cryptography">Google Payment
 *     Method Token standard</a>
 * @since 1.0.0
 */
public final class PaymentMethodTokenRecipient {
  private final String protocolVersion;
  private final List<SenderVerifyingKeysProvider> senderVerifyingKeysProviders;
  private final List<HybridDecrypt> hybridDecrypters = new ArrayList<>();
  private final String senderId;
  private final String recipientId;
  private final String contextInfo;

  PaymentMethodTokenRecipient(
      String protocolVersion,
      List<SenderVerifyingKeysProvider> senderVerifyingKeysProviders,
      String senderId,
      List<ECPrivateKey> recipientPrivateKeys,
      List<PaymentMethodTokenRecipientKem> recipientKems,
      String recipientId,
      String contextInfo)

      throws GeneralSecurityException {
    if (!protocolVersion.equals(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V1)
        && !protocolVersion.equals(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)
        && !protocolVersion.equals(
            PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)) {
      throw new IllegalArgumentException("invalid version: " + protocolVersion);
    }
    this.protocolVersion = protocolVersion;
    if (senderVerifyingKeysProviders == null || senderVerifyingKeysProviders.isEmpty()) {
      throw new IllegalArgumentException(
          "must set at least one way to get sender's verifying key using"
              + " Builder.fetchSenderVerifyingKeysWith or Builder.senderVerifyingKeys");
    }
    this.senderVerifyingKeysProviders = senderVerifyingKeysProviders;
    this.senderId = senderId;

    ProtocolVersionConfig protocolVersionConfig =
        ProtocolVersionConfig.forProtocolVersion(protocolVersion);
    if (protocolVersionConfig.isEncryptionRequired) {
      if (recipientPrivateKeys.isEmpty() && recipientKems.isEmpty()) {
        throw new IllegalArgumentException(
            "must add at least one recipient's decrypting key using Builder.addRecipientPrivateKey "
                + "or Builder.addRecipientKem");
      }
      for (ECPrivateKey privateKey : recipientPrivateKeys) {
        hybridDecrypters.add(
            new PaymentMethodTokenHybridDecrypt(privateKey, protocolVersionConfig));
      }
      for (PaymentMethodTokenRecipientKem kem : recipientKems) {
        hybridDecrypters.add(new PaymentMethodTokenHybridDecrypt(kem, protocolVersionConfig));
      }
    } else {
      if (!recipientPrivateKeys.isEmpty() || !recipientKems.isEmpty()) {
        throw new IllegalArgumentException(
            "must not set private decrypting key using Builder.addRecipientPrivateKey "
                + "or Builder.addRecipientDecrypter");
      }
    }

    if (recipientId == null) {
      throw new IllegalArgumentException("must set recipient Id using Builder.recipientId");
    }
    this.recipientId = recipientId;
    this.contextInfo = contextInfo;
  }

  private PaymentMethodTokenRecipient(Builder builder) throws GeneralSecurityException {
    this(
        builder.protocolVersion,
        builder.senderVerifyingKeysProviders,
        builder.senderId,
        builder.recipientPrivateKeys,
        builder.recipientKems,
        builder.recipientId,
        builder.contextInfo);
  }

  /**
   * Builder for {@link PaymentMethodTokenRecipient}.
   *
   * @since 1.0.0
   */
  public static class Builder {
    private String protocolVersion = PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V1;
    private String senderId = PaymentMethodTokenConstants.GOOGLE_SENDER_ID;
    private String contextInfo = PaymentMethodTokenConstants.GOOGLE_CONTEXT_INFO_ECV1;
    private String recipientId = null;
    private final List<SenderVerifyingKeysProvider> senderVerifyingKeysProviders =
        new ArrayList<SenderVerifyingKeysProvider>();
    private final List<ECPrivateKey> recipientPrivateKeys = new ArrayList<ECPrivateKey>();
    private final List<PaymentMethodTokenRecipientKem> recipientKems = new ArrayList<>();

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

    /** Sets the contextInfo. */
    public Builder contextInfo(String val) {
      contextInfo = val;
      return this;
    }

    /**
     * Fetches verifying public keys of the sender using {@link GooglePaymentsPublicKeysManager}.
     *
     * <p>This is the preferred method of specifying the verifying public keys of the sender.
     */
    public Builder fetchSenderVerifyingKeysWith(
        final GooglePaymentsPublicKeysManager googlePaymentsPublicKeysManager)
        throws GeneralSecurityException {
      this.senderVerifyingKeysProviders.add(
          new SenderVerifyingKeysProvider() {
            @Override
            public List<ECPublicKey> get(String protocolVersion) throws GeneralSecurityException {
              try {
                return parseTrustedSigningKeysJson(
                    protocolVersion, googlePaymentsPublicKeysManager.getTrustedSigningKeysJson());
              } catch (IOException e) {
                throw new GeneralSecurityException("Failed to fetch keys!", e);
              }
            }
          });
      return this;
    }

    /**
     * Sets the trusted verifying public keys of the sender.
     *
     * <p><b>IMPORTANT</b>: Instead of using this method to set the verifying public keys of the
     * sender, prefer calling {@link #fetchSenderVerifyingKeysWith} passing it an instance of {@link
     * GooglePaymentsPublicKeysManager}. It will take care of fetching fresh keys and caching in
     * memory. Only use this method if you can't use {@link #fetchSenderVerifyingKeysWith} and be
     * aware you will need to handle Google key rotations yourself.
     *
     * <p>The given string is a JSON object formatted like the following:
     *
     * <pre>
     * {
     *   "keys": [
     *     {
     *       "keyValue": "encoded public key",
     *       "protocolVersion": "ECv1"
     *     },
     *     {
     *       "keyValue": "encoded public key",
     *       "protocolVersion": "ECv1"
     *     },
     *   ],
     * }
     * </pre>
     *
     * <p>Each public key will be a base64 (no wrapping, padded) version of the key encoded in ASN.1
     * type SubjectPublicKeyInfo defined in the X.509 standard.
     */
    public Builder senderVerifyingKeys(final String trustedSigningKeysJson)
        throws GeneralSecurityException {
      this.senderVerifyingKeysProviders.add(
          new SenderVerifyingKeysProvider() {
            @Override
            public List<ECPublicKey> get(String protocolVersion) throws GeneralSecurityException {
              return parseTrustedSigningKeysJson(protocolVersion, trustedSigningKeysJson);
            }
          });
      return this;
    }

    /**
     * Adds a verifying public key of the sender.
     *
     * <p><b>IMPORTANT</b>: Instead of using this method to set the verifying public keys of the
     * sender, prefer calling {@link #fetchSenderVerifyingKeysWith} passing it an instance of {@link
     * GooglePaymentsPublicKeysManager}. It will take care of fetching fresh keys and caching in
     * memory. Only use this method if you can't use {@link #fetchSenderVerifyingKeysWith} and be
     * aware you will need to handle Google key rotations yourself.
     *
     * <p>The public key is a base64 (no wrapping, padded) version of the key encoded in ASN.1 type
     * SubjectPublicKeyInfo defined in the X.509 standard.
     *
     * <p>Multiple keys may be added. This utility will then verify any message signed with any of
     * the private keys corresponding to the public keys added. Adding multiple keys is useful for
     * handling key rotation.
     */
    public Builder addSenderVerifyingKey(final String val) throws GeneralSecurityException {
      this.senderVerifyingKeysProviders.add(
          new SenderVerifyingKeysProvider() {
            @Override
            public List<ECPublicKey> get(String protocolVersion) throws GeneralSecurityException {
              return Collections.singletonList(PaymentMethodTokenUtil.x509EcPublicKey(val));
            }
          });
      return this;
    }

    /**
     * Adds a verifying public key of the sender.
     *
     * <p><b>IMPORTANT</b>: Instead of using this method to set the verifying public keys of the
     * sender, prefer calling {@link #fetchSenderVerifyingKeysWith} passing it an instance of {@link
     * GooglePaymentsPublicKeysManager}. It will take care of fetching fresh keys and caching in
     * memory. Only use this method if you can't use {@link #fetchSenderVerifyingKeysWith} and be
     * aware you will need to handle Google key rotations yourself.
     */
    public Builder addSenderVerifyingKey(final ECPublicKey val) throws GeneralSecurityException {
      this.senderVerifyingKeysProviders.add(
          new SenderVerifyingKeysProvider() {
            @Override
            public List<ECPublicKey> get(String protocolVersion) throws GeneralSecurityException {
              return Collections.singletonList(val);
            }
          });
      return this;
    }

    /**
     * Adds the decryption private key of the recipient.
     *
     * <p>It must be base64 encoded PKCS8 private key.
     */
    public Builder addRecipientPrivateKey(String val) throws GeneralSecurityException {
      return addRecipientPrivateKey(PaymentMethodTokenUtil.pkcs8EcPrivateKey(val));
    }

    /** Adds the decryption private key of the recipient. */
    public Builder addRecipientPrivateKey(ECPrivateKey val) throws GeneralSecurityException {
      recipientPrivateKeys.add(val);
      return this;
    }

    /**
     * Adds a custom {@link PaymentMethodTokenRecipientKem}.
     *
     * <p>This is useful for clients that store keys in an HSM and need a more control on how the
     * key is used. If you are not using an HSM, you probably should just use {@link
     * #addRecipientPrivateKey}.
     *
     * @since 1.1.0
     */
    public Builder addRecipientKem(PaymentMethodTokenRecipientKem kem) {
      recipientKems.add(kem);
      return this;
    }

    public PaymentMethodTokenRecipient build() throws GeneralSecurityException {
      return new PaymentMethodTokenRecipient(this);
    }
  }

  /**
   * Unseal the given {@code sealedMessage} by performing the necessary signature verification and
   * decryption (if required) steps based on the protocolVersion.
   */
  public String unseal(final String sealedMessage) throws GeneralSecurityException {
    try {
      if (protocolVersion.equals(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V1)) {
        return unsealECV1(sealedMessage);
      } else if (protocolVersion.equals(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2)) {
        return unsealECV2(sealedMessage);
      } else if (protocolVersion.equals(
          PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2_SIGNING_ONLY)) {
        return unsealECV2SigningOnly(sealedMessage);
      }
      throw new IllegalArgumentException("unsupported version: " + protocolVersion);
    } catch (JsonParseException | IllegalStateException e) {
      throw new GeneralSecurityException("cannot unseal; invalid JSON message", e);
    }
  }

  private String unsealECV1(String sealedMessage) throws GeneralSecurityException {
    JsonObject jsonMsg = JsonParser.parseString(sealedMessage).getAsJsonObject();
    validateECV1(jsonMsg);
    String signedMessage = verifyECV1(jsonMsg);
    String decryptedMessage = decrypt(signedMessage);
    validateMessage(decryptedMessage);
    return decryptedMessage;
  }

  private String unsealECV2(String sealedMessage) throws GeneralSecurityException {
    JsonObject jsonMsg = JsonParser.parseString(sealedMessage).getAsJsonObject();
    validateECV2(jsonMsg);
    String signedMessage = verifyECV2(jsonMsg);
    String decryptedMessage = decrypt(signedMessage);
    validateMessage(decryptedMessage);
    return decryptedMessage;
  }

  private String unsealECV2SigningOnly(String sealedMessage) throws GeneralSecurityException {
    JsonObject jsonMsg = JsonParser.parseString(sealedMessage).getAsJsonObject();
    validateECV2(jsonMsg);
    String message = verifyECV2(jsonMsg);
    validateMessage(message);
    return message;
  }

  private String verifyECV1(final JsonObject jsonMsg) throws GeneralSecurityException {
    byte[] signature =
        Base64.decode(jsonMsg.get(PaymentMethodTokenConstants.JSON_SIGNATURE_KEY).getAsString());
    String signedMessage =
        jsonMsg.get(PaymentMethodTokenConstants.JSON_SIGNED_MESSAGE_KEY).getAsString();
    byte[] signedBytes = getSignedBytes(protocolVersion, signedMessage);
    verify(
        protocolVersion,
        senderVerifyingKeysProviders,
        Collections.singletonList(signature),
        signedBytes);
    return signedMessage;
  }

  private String verifyECV2(final JsonObject jsonMsg) throws GeneralSecurityException {
    byte[] signature =
        Base64.decode(jsonMsg.get(PaymentMethodTokenConstants.JSON_SIGNATURE_KEY).getAsString());
    String signedMessage =
        jsonMsg.get(PaymentMethodTokenConstants.JSON_SIGNED_MESSAGE_KEY).getAsString();
    byte[] signedBytes = getSignedBytes(protocolVersion, signedMessage);
    verify(
        protocolVersion,
        verifyIntermediateSigningKey(jsonMsg),
        Collections.singletonList(signature),
        signedBytes);
    return signedMessage;
  }

  private byte[] getSignedBytes(String protocolVersion, String signedMessage)
      throws GeneralSecurityException {
    return PaymentMethodTokenUtil.toLengthValue(
        // The order of the parameters matters.
        senderId, recipientId, protocolVersion, signedMessage);
  }

  private void validateMessage(String decryptedMessage) throws GeneralSecurityException {
    JsonObject decodedMessage;

    try {
      decodedMessage = JsonParser.parseString(decryptedMessage).getAsJsonObject();
    } catch (JsonParseException | IllegalStateException e) {
      // Message wasn't a valid JSON, so nothing to validate.
      return;
    }

    // If message expiration is present, checking it.
    if (decodedMessage.has(PaymentMethodTokenConstants.JSON_MESSAGE_EXPIRATION_KEY)) {
      long expirationInMillis =
          Long.parseLong(
              decodedMessage
                  .get(PaymentMethodTokenConstants.JSON_MESSAGE_EXPIRATION_KEY)
                  .getAsString());
      if (expirationInMillis <= Instant.now().getMillis()) {
        throw new GeneralSecurityException("expired payload");
      }
    }
  }

  private static void verify(
      final String protocolVersion,
      final List<SenderVerifyingKeysProvider> senderVerifyingKeysProviders,
      final List<byte[]> signatures,
      final byte[] signedBytes)
      throws GeneralSecurityException {
    boolean verified = false;
    for (SenderVerifyingKeysProvider verifyingKeysProvider : senderVerifyingKeysProviders) {
      for (ECPublicKey publicKey : verifyingKeysProvider.get(protocolVersion)) {
        EcdsaVerifyJce verifier =
            new EcdsaVerifyJce(
                publicKey, PaymentMethodTokenConstants.ECDSA_HASH_SHA256, EcdsaEncoding.DER);
        for (byte[] signature : signatures) {
          try {
            verifier.verify(signature, signedBytes);
            // No exception means the signature is valid.
            verified = true;
          } catch (GeneralSecurityException e) {
            // ignored, try again
          }
        }
      }
    }
    if (!verified) {
      throw new GeneralSecurityException("cannot verify signature");
    }
  }

  private String decrypt(String ciphertext) throws GeneralSecurityException {
    for (HybridDecrypt hybridDecrypter : hybridDecrypters) {
      try {
        byte[] cleartext =
            hybridDecrypter.decrypt(
                ciphertext.getBytes(UTF_8), this.contextInfo);
        return new String(cleartext, UTF_8);
      } catch (GeneralSecurityException e) {
        // ignored, try again
      }
    }
    throw new GeneralSecurityException("cannot decrypt");
  }

  private void validateECV1(final JsonObject jsonMsg) throws GeneralSecurityException {
    if (!jsonMsg.has(PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY)
        || !jsonMsg.has(PaymentMethodTokenConstants.JSON_SIGNATURE_KEY)
        || !jsonMsg.has(PaymentMethodTokenConstants.JSON_SIGNED_MESSAGE_KEY)
        || jsonMsg.size() != 3) {
      throw new GeneralSecurityException(
          "ECv1 message must contain exactly protocolVersion, signature and signedMessage");
    }
    String version =
        jsonMsg.get(PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY).getAsString();
    if (!version.equals(protocolVersion)) {
      throw new GeneralSecurityException("invalid version: " + version);
    }
  }

  private void validateECV2(final JsonObject jsonMsg) throws GeneralSecurityException {
    if (!jsonMsg.has(PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY)
        || !jsonMsg.has(PaymentMethodTokenConstants.JSON_SIGNATURE_KEY)
        || !jsonMsg.has(PaymentMethodTokenConstants.JSON_SIGNED_MESSAGE_KEY)
        || !jsonMsg.has(PaymentMethodTokenConstants.JSON_INTERMEDIATE_SIGNING_KEY)) {
      throw new GeneralSecurityException(
          protocolVersion
              + " message must contain protocolVersion, intermediateSigningKey, "
              + "signature and signedMessage");
    }
    String version =
        jsonMsg.get(PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY).getAsString();
    if (!version.equals(protocolVersion)) {
      throw new GeneralSecurityException("invalid version: " + version);
    }
  }

  /**
   * Verifies the intermediate key and returns a singleton list containing of {@code
   * SenderVerifyingKeysProvider} that provides the verified key.
   */
  private List<SenderVerifyingKeysProvider> verifyIntermediateSigningKey(JsonObject jsonMsg)
      throws GeneralSecurityException {
    JsonObject intermediateSigningKey =
        jsonMsg.get(PaymentMethodTokenConstants.JSON_INTERMEDIATE_SIGNING_KEY).getAsJsonObject();
    validateIntermediateSigningKey(intermediateSigningKey);
    ArrayList<byte[]> signatures = new ArrayList<>();
    JsonArray signaturesJson =
        intermediateSigningKey
            .get(PaymentMethodTokenConstants.JSON_SIGNATURES_KEY)
            .getAsJsonArray();
    for (int i = 0; i < signaturesJson.size(); i++) {
      signatures.add(Base64.decode(signaturesJson.get(i).getAsString()));
    }
    String signedKeyAsString =
        intermediateSigningKey.get(PaymentMethodTokenConstants.JSON_SIGNED_KEY_KEY).getAsString();
    byte[] signedBytes =
        PaymentMethodTokenUtil.toLengthValue(
            // The order of the parameters matters.
            senderId, protocolVersion, signedKeyAsString);
    verify(protocolVersion, senderVerifyingKeysProviders, signatures, signedBytes);
    JsonObject signedKey = JsonParser.parseString(signedKeyAsString).getAsJsonObject();
    validateSignedKey(signedKey);
    final String key = signedKey.get(PaymentMethodTokenConstants.JSON_KEY_VALUE_KEY).getAsString();
    SenderVerifyingKeysProvider provider =
        new SenderVerifyingKeysProvider() {
          @Override
          public List<ECPublicKey> get(String protocolVersion) throws GeneralSecurityException {
            if (PaymentMethodTokenRecipient.this.protocolVersion.equals(protocolVersion)) {
              return Collections.singletonList(PaymentMethodTokenUtil.x509EcPublicKey(key));
            } else {
              return Collections.emptyList();
            }
          }
        };
    return Collections.singletonList(provider);
  }

  private JsonObject validateIntermediateSigningKey(final JsonObject intermediateSigningKey)
      throws GeneralSecurityException {
    if (!intermediateSigningKey.has(PaymentMethodTokenConstants.JSON_SIGNATURES_KEY)
        || !intermediateSigningKey.has(PaymentMethodTokenConstants.JSON_SIGNED_KEY_KEY)
        || intermediateSigningKey.size() != 2) {
      throw new GeneralSecurityException(
          "intermediateSigningKey must contain exactly signedKey and signatures");
    }
    return intermediateSigningKey;
  }

  private void validateSignedKey(final JsonObject signedKey) throws GeneralSecurityException {
    // Note: allowing further keys to be added so we can extend the protocol if needed in the future
    if (!signedKey.has(PaymentMethodTokenConstants.JSON_KEY_VALUE_KEY)
        || !signedKey.has(PaymentMethodTokenConstants.JSON_KEY_EXPIRATION_KEY)) {
      throw new GeneralSecurityException(
          "intermediateSigningKey.signedKey must contain keyValue and keyExpiration");
    }

    // If message expiration is present, checking it.
    long expirationInMillis =
        Long.parseLong(
            signedKey.get(PaymentMethodTokenConstants.JSON_KEY_EXPIRATION_KEY).getAsString());
    if (expirationInMillis <= Instant.now().getMillis()) {
      throw new GeneralSecurityException("expired intermediateSigningKey");
    }
  }

  private static List<ECPublicKey> parseTrustedSigningKeysJson(
      String protocolVersion, String trustedSigningKeysJson) throws GeneralSecurityException {
    List<ECPublicKey> senderVerifyingKeys = new ArrayList<>();
    try {
      JsonArray keys =
          JsonParser.parseString(trustedSigningKeysJson)
              .getAsJsonObject()
              .get("keys")
              .getAsJsonArray();
      for (int i = 0; i < keys.size(); i++) {
        JsonObject key = keys.get(i).getAsJsonObject();
        if (protocolVersion.equals(
            key.get(PaymentMethodTokenConstants.JSON_PROTOCOL_VERSION_KEY).getAsString())) {

          if (key.has(PaymentMethodTokenConstants.JSON_KEY_EXPIRATION_KEY)) {
            // If message expiration is present, checking it.
            long expirationInMillis =
                Long.parseLong(
                    key.get(PaymentMethodTokenConstants.JSON_KEY_EXPIRATION_KEY).getAsString());
            if (expirationInMillis <= Instant.now().getMillis()) {
              // Ignore expired keys
              continue;
            }
          } else if (!protocolVersion.equals(PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V1)) {
            // keyExpiration is required in all versions except ECv1, so if it is missing we should
            // skip using this key.
            // In ECv1 the expiration is optional because it is assumed that the caller is
            // respecting the HTTP cache headers and not using the trustedSigningKeysJson that are
            // expired according to the headers.
            continue;
          }

          senderVerifyingKeys.add(
              PaymentMethodTokenUtil.x509EcPublicKey(key.get("keyValue").getAsString()));
        }
      }
    } catch (JsonParseException | IllegalStateException e) {
      throw new GeneralSecurityException("failed to extract trusted signing public keys", e);
    }
    if (senderVerifyingKeys.isEmpty()) {
      throw new GeneralSecurityException("no trusted keys are available for this protocol version");
    }
    return senderVerifyingKeys;
  }

  private interface SenderVerifyingKeysProvider {
    List<ECPublicKey> get(String protocolVersion) throws GeneralSecurityException;
  }
}
