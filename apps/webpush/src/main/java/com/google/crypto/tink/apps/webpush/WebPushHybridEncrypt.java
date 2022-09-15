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

package com.google.crypto.tink.apps.webpush;

import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.Random;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A {@link HybridEncrypt} implementation for the hybrid encryption used in <a
 * href="https://tools.ietf.org/html/rfc8291">RFC 8291 - Web Push Message Encryption</a>.
 *
 * <h3>Ciphertext format</h3>
 *
 * <p>When used with <a href="https://tools.ietf.org/html/rfc8291#section-4">AES128-GCM content
 * encoding</a>, which is the only content encoding supported in this implementation, the ciphertext
 * is formatted according to RFC 8188 section 2, and looks as follows
 *
 * <pre>
 * // NOLINTNEXTLINE
 * +-----------+----------------+------------------+---------------------------------------------------
 * | salt (16) | recordsize (4) | publickeylen (1) | publickey (publickeylen) | aes128-gcm-ciphertext |
 * +-----------+----------------+------------------+---------------------------------------------------
 * </pre>
 *
 * <p>RFC 8188 divides messages into records which are encrypted independently. Web Push messages
 * cannot be longer than 3993 bytes, and are always encrypted in a single record with default size
 * of 4096 bytes. {@code aes128-gcm-ciphertext} is the encryption of the message padded with a
 * single byte of value {@code 0x02} (which indicates that this is the last and only record).
 *
 * <h3>Usage</h3>
 *
 * <pre>{@code
 * import com.google.crypto.tink.HybridDecrypt;
 * import com.google.crypto.tink.HybridEncrypt;
 * import java.security.interfaces.ECPrivateKey;
 * import java.security.interfaces.ECPublicKey;
 *
 * // Encryption.
 * ECPublicKey reicipientPublicKey = ...;
 * byte[] authSecret = ...;
 * HybridEncrypt hybridEncrypt = new WebPushHybridEncrypt.Builder()
 *      .withAuthSecret(authSecret)
 *      .withRecipientPublicKey(recipientPublicKey)
 *      .build();
 * byte[] plaintext = ...;
 * byte[] ciphertext = hybridEncrypt.encrypt(plaintext, null);
 *
 * // Decryption.
 * ECPrivateKey recipientPrivateKey = ...;
 * HybridDecrypt hybridDecrypt = new WebPushHybridDecrypt.Builder()
 *      .withAuthSecret(authSecret)
 *      .withRecipientPublicKey(recipientPublicKey)
 *      .withRecipientPrivateKey(recipientPrivateKey)
 *      .build();
 * byte[] plaintext = hybridDecrypt.decrypt(ciphertext, null);
 * }</pre>
 *
 * @since 1.1.0
 */
public final class WebPushHybridEncrypt implements HybridEncrypt {
  private final byte[] recipientPublicKey;
  private final byte[] authSecret;
  private final ECPoint recipientPublicPoint;
  private final int recordSize;
  private final int paddingSize;

  private WebPushHybridEncrypt(Builder builder) throws GeneralSecurityException {
    if (builder.recipientPublicKey == null || builder.recipientPublicPoint == null) {
      throw new IllegalArgumentException(
          "must set recipient's public key with Builder.withRecipientPublicKey");
    }
    this.recipientPublicKey = builder.recipientPublicKey;
    this.recipientPublicPoint = builder.recipientPublicPoint;

    if (builder.authSecret == null) {
      throw new IllegalArgumentException("must set auth secret with Builder.withAuthSecret");
    }
    if (builder.authSecret.length != WebPushConstants.AUTH_SECRET_SIZE) {
      throw new IllegalArgumentException(
          "auth secret must have " + WebPushConstants.AUTH_SECRET_SIZE + " bytes");
    }
    this.authSecret = builder.authSecret;
    this.recordSize = builder.recordSize;
    this.paddingSize = builder.paddingSize;
  }

  /**
   * Builder for {@link WebPushHybridEncrypt}.
   *
   * @since 1.1.0
   */
  public static final class Builder {
    private byte[] recipientPublicKey = null;
    private ECPoint recipientPublicPoint = null;
    private byte[] authSecret = null;
    private int recordSize = WebPushConstants.MAX_CIPHERTEXT_SIZE;
    private int paddingSize = WebPushConstants.DEFAULT_PADDING_SIZE;

    public Builder() {}

    /**
     * Sets the record size.
     *
     * <p>If set, this value must match the record size set with {@link
     * WebPushHybridEncrypt.Builder#withRecordSize}.
     *
     * <p>If not set, a record size of 4096 bytes is used. This value should work for most users.
     */
    @CanIgnoreReturnValue
    public Builder withRecordSize(int val) {
      if (val < WebPushConstants.CIPHERTEXT_OVERHEAD
          || val > WebPushConstants.MAX_CIPHERTEXT_SIZE) {
        throw new IllegalArgumentException(
            String.format(
                "invalid record size (%s); must be a number between [%s, %s]",
                val, WebPushConstants.CIPHERTEXT_OVERHEAD, WebPushConstants.MAX_CIPHERTEXT_SIZE));
      }

      recordSize = val;
      return this;
    }

    /**
     * Sets the padding size which is default to 0.
     *
     * <p>The padding size cannot be larger than
     */
    @CanIgnoreReturnValue
    public Builder withPaddingSize(int val) {
      if (val < 0
          || val > WebPushConstants.MAX_CIPHERTEXT_SIZE - WebPushConstants.CIPHERTEXT_OVERHEAD) {
        throw new IllegalArgumentException(
            String.format(
                "invalid padding size (%s); must be a number between [%s, %s]",
                val,
                0,
                WebPushConstants.MAX_CIPHERTEXT_SIZE - WebPushConstants.CIPHERTEXT_OVERHEAD));
      }

      paddingSize = val;
      return this;
    }

    /** Sets the authentication secret. */
    @CanIgnoreReturnValue
    public Builder withAuthSecret(final byte[] val) {
      authSecret = val.clone();
      return this;
    }

    /** Sets the public key of the recipient. */
    @CanIgnoreReturnValue
    public Builder withRecipientPublicKey(ECPublicKey val) throws GeneralSecurityException {
      recipientPublicPoint = val.getW();
      recipientPublicKey =
          EllipticCurves.pointEncode(
              WebPushConstants.NIST_P256_CURVE_TYPE,
              WebPushConstants.UNCOMPRESSED_POINT_FORMAT,
              val.getW());

      return this;
    }

    /**
     * Sets the public key of the recipient.
     *
     * <p>The public key must be formatted as an uncompressed point format, i.e., it has {@code 65}
     * bytes and the first byte must be {@code 0x04}.
     */
    @CanIgnoreReturnValue
    public Builder withRecipientPublicKey(final byte[] val) throws GeneralSecurityException {
      recipientPublicKey = val.clone();
      recipientPublicPoint =
          EllipticCurves.pointDecode(
              WebPushConstants.NIST_P256_CURVE_TYPE,
              WebPushConstants.UNCOMPRESSED_POINT_FORMAT,
              recipientPublicKey);
      return this;
    }

    public WebPushHybridEncrypt build() throws GeneralSecurityException {
      return new WebPushHybridEncrypt(this);
    }
  }

  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] contextInfo /* unused */)
      throws GeneralSecurityException {
    if (contextInfo != null) {
      throw new GeneralSecurityException("contextInfo must be null because it is unused");
    }

    if (plaintext.length > recordSize - paddingSize - WebPushConstants.CIPHERTEXT_OVERHEAD) {
      throw new GeneralSecurityException(
          String.format(
              "plaintext too long; with record size = %d and padding size = %d, plaintext cannot"
                  + " be longer than %d",
              recordSize,
              paddingSize,
              recordSize - paddingSize - WebPushConstants.CIPHERTEXT_OVERHEAD));
    }

    // See https://tools.ietf.org/html/rfc8291#section-3.4.
    KeyPair keyPair = EllipticCurves.generateKeyPair(WebPushConstants.NIST_P256_CURVE_TYPE);
    ECPrivateKey ephemeralPrivateKey = (ECPrivateKey) keyPair.getPrivate();
    ECPublicKey ephemeralPublicKey = (ECPublicKey) keyPair.getPublic();
    byte[] ecdhSecret =
        EllipticCurves.computeSharedSecret(ephemeralPrivateKey, recipientPublicPoint);
    byte[] ephemeralPublicKeyBytes =
        EllipticCurves.pointEncode(
            WebPushConstants.NIST_P256_CURVE_TYPE,
            WebPushConstants.UNCOMPRESSED_POINT_FORMAT,
            ephemeralPublicKey.getW());
    byte[] ikm =
        WebPushUtil.computeIkm(ecdhSecret, authSecret, recipientPublicKey, ephemeralPublicKeyBytes);
    byte[] salt = Random.randBytes(WebPushConstants.SALT_SIZE);
    byte[] cek = WebPushUtil.computeCek(ikm, salt);
    byte[] nonce = WebPushUtil.computeNonce(ikm, salt);
    return ByteBuffer.allocate(
            WebPushConstants.CIPHERTEXT_OVERHEAD + plaintext.length + paddingSize)
        .put(salt)
        .putInt(recordSize)
        .put((byte) WebPushConstants.PUBLIC_KEY_SIZE)
        .put(ephemeralPublicKeyBytes)
        .put(encrypt(cek, nonce, plaintext))
        .array();
  }

  private byte[] encrypt(final byte[] key, final byte[] nonce, final byte[] plaintext)
      throws GeneralSecurityException {
    Cipher cipher = EngineFactory.CIPHER.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec params = new GCMParameterSpec(8 * WebPushConstants.TAG_SIZE, nonce);
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), params);
    byte[] paddedPlaintext = new byte[plaintext.length + 1 + paddingSize];
    paddedPlaintext[plaintext.length] = WebPushConstants.PADDING_DELIMITER_BYTE;
    System.arraycopy(plaintext, 0, paddedPlaintext, 0, plaintext.length);
    return cipher.doFinal(paddedPlaintext);
  }
}
