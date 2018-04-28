// Copyright 2018 Google Inc.
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

import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.apps.paymentmethodtoken.PaymentMethodTokenConstants.ProtocolVersionConfig;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.EcdsaSignJce;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPrivateKey;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Creates a signed certificate with the intermediate signing keys used by the sender in certain
 * protocol versions.
 *
 * @since 1.1.0
 */
public class SenderIntermediateCertFactory {
  private final List<PublicKeySign> signers;
  private final String intermediateSigningKey;
  private final String protocolVersion;
  private final String senderId;
  private final long expiration;

  private SenderIntermediateCertFactory(
      String protocolVersion,
      String senderId,
      List<ECPrivateKey> senderSigningKeys,
      String intermediateSigningKey,
      long expiration) {
    if (!ProtocolVersionConfig.forProtocolVersion(protocolVersion)
        .supportsIntermediateSigningKeys) {
      throw new IllegalArgumentException("invalid version: " + protocolVersion);
    }
    if (senderSigningKeys.isEmpty()) {
      throw new IllegalArgumentException(
          "must add at least one sender's signing key using Builder.addSenderSigningKey");
    }
    if (expiration == 0) {
      throw new IllegalArgumentException("must set expiration using Builder.expiration");
    }
    if (expiration < 0) {
      throw new IllegalArgumentException("invalid negative expiration");
    }
    this.protocolVersion = protocolVersion;
    this.senderId = senderId;
    this.signers = new ArrayList<>();
    for (ECPrivateKey senderSigningKey : senderSigningKeys) {
      this.signers.add(
          new EcdsaSignJce(
              senderSigningKey, PaymentMethodTokenConstants.ECDSA_SHA256_SIGNING_ALGO));
    }
    this.intermediateSigningKey = intermediateSigningKey;
    this.expiration = expiration;
  }

  /**
   * Builder for {@link SenderIntermediateCertFactory}.
   *
   * @since 1.1.0
   */
  public static class Builder {
    private List<ECPrivateKey> senderSigningKeys = new ArrayList<>();
    private String intermediateSigningKey;
    private String protocolVersion = PaymentMethodTokenConstants.PROTOCOL_VERSION_EC_V2;
    private String senderId = PaymentMethodTokenConstants.GOOGLE_SENDER_ID;
    private long expiration;

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

    /** Sets the expiration in millis since epoch. */
    public Builder expiration(long millisSinceEpoch) {
      expiration = millisSinceEpoch;
      return this;
    }

    /**
     * Adds a signing key of the sender.
     *
     * <p>It must be base64 encoded PKCS8 private key.
     */
    public Builder addSenderSigningKey(String val) throws GeneralSecurityException {
      return addSenderSigningKey(PaymentMethodTokenUtil.pkcs8EcPrivateKey(val));
    }

    /**
     * Adds a signing key of the sender.
     *
     * <p>It must be base64 encoded PKCS8 private key.
     */
    public Builder addSenderSigningKey(ECPrivateKey val) throws GeneralSecurityException {
      this.senderSigningKeys.add(val);
      return this;
    }

    /**
     * Sets the intermediate signing key being signed.
     *
     * <p>The public key specified here is a base64 (no wrapping, padded) version of the key encoded
     * in ASN.1 type SubjectPublicKeyInfo defined in the X.509 standard.
     */
    public Builder senderIntermediateSigningKey(String val) throws GeneralSecurityException {
      // Parsing to validate the format
      PaymentMethodTokenUtil.x509EcPublicKey(val);
      intermediateSigningKey = val;
      return this;
    }

    public SenderIntermediateCertFactory build() throws GeneralSecurityException {
      return new SenderIntermediateCertFactory(
          protocolVersion, senderId, senderSigningKeys, intermediateSigningKey, expiration);
    }
  }

  /**
   * Creates the certificate.
   *
   * <p>This will return a serialized JSONObject in the following format:
   *
   * <pre>
   *   {
   *     // {
   *     //   // A string that identifies this cert
   *     //   "keyValue": "ZXBoZW1lcmFsUHVibGljS2V5"
   *     //   // string (UTC milliseconds since epoch)
   *     //   "expiration": "1520836260646",
   *     // }
   *     "signedKey": "... serialized JSON shown in comment above ...",
   *     "signatures": ["signature1", "signature2", ...],
   *   }
   * </pre>
   */
  public String create() throws GeneralSecurityException {
    try {
      String signedKey =
          new JSONObject()
              .put(PaymentMethodTokenConstants.JSON_KEY_VALUE_KEY, intermediateSigningKey)
              .put(PaymentMethodTokenConstants.JSON_KEY_EXPIRATION_KEY, Long.toString(expiration))
              .toString();
      byte[] toSignBytes =
          PaymentMethodTokenUtil.toLengthValue(
              // The order of the parameters matters.
              senderId, protocolVersion, signedKey);
      JSONArray signatures = new JSONArray();
      for (PublicKeySign signer : signers) {
        byte[] signature = signer.sign(toSignBytes);
        signatures.put(Base64.encode(signature));
      }
      return new JSONObject()
          .put(PaymentMethodTokenConstants.JSON_SIGNED_KEY_KEY, signedKey)
          .put(PaymentMethodTokenConstants.JSON_SIGNATURES_KEY, signatures)
          .toString();
    } catch (JSONException e) {
      throw new RuntimeException("Failed to perform JSON encoding", e);
    }
  }
}
