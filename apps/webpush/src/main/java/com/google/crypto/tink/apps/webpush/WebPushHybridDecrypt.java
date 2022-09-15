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

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A {@link HybridDecrypt} implementation for the hybrid encryption used in <a
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
public final class WebPushHybridDecrypt implements HybridDecrypt {
  private final ECPrivateKey recipientPrivateKey;
  private final byte[] recipientPublicKey;
  private final byte[] authSecret;
  private final int recordSize;

  private WebPushHybridDecrypt(Builder builder) throws GeneralSecurityException {
    if (builder.recipientPrivateKey == null) {
      throw new IllegalArgumentException(
          "must set recipient's private key with Builder.withRecipientPrivateKey");
    }
    this.recipientPrivateKey = builder.recipientPrivateKey;

    if (builder.recipientPublicKey == null
        || builder.recipientPublicKey.length != WebPushConstants.PUBLIC_KEY_SIZE) {
      throw new IllegalArgumentException(
          "recipient public key must have " + WebPushConstants.PUBLIC_KEY_SIZE + " bytes");
    }
    this.recipientPublicKey = builder.recipientPublicKey;

    if (builder.authSecret == null) {
      throw new IllegalArgumentException("must set auth secret with Builder.withAuthSecret");
    }
    if (builder.authSecret.length != WebPushConstants.AUTH_SECRET_SIZE) {
      throw new IllegalArgumentException(
          "auth secret must have " + WebPushConstants.AUTH_SECRET_SIZE + " bytes");
    }
    this.authSecret = builder.authSecret;

    if (builder.recordSize < WebPushConstants.CIPHERTEXT_OVERHEAD
        || builder.recordSize > WebPushConstants.MAX_CIPHERTEXT_SIZE) {
      throw new IllegalArgumentException(
          String.format(
              "invalid record size (%s); must be a number between [%s, %s]",
              builder.recordSize,
              WebPushConstants.CIPHERTEXT_OVERHEAD,
              WebPushConstants.MAX_CIPHERTEXT_SIZE));
    }
    this.recordSize = builder.recordSize;
  }

  /**
   * Builder for {@link WebPushHybridDecrypt}.
   *
   * @since 1.1.0
   */
  public static final class Builder {
    private ECPrivateKey recipientPrivateKey = null;
    private byte[] recipientPublicKey = null;
    private byte[] authSecret = null;
    private int recordSize = WebPushConstants.MAX_CIPHERTEXT_SIZE;

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
      recordSize = val;
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
    public Builder withRecipientPublicKey(final byte[] val) {
      recipientPublicKey = val.clone();
      return this;
    }

    /** Sets the private key of the recipient. */
    @CanIgnoreReturnValue
    public Builder withRecipientPrivateKey(ECPrivateKey val) throws GeneralSecurityException {
      recipientPrivateKey = val;
      return this;
    }

    /**
     * Sets the private key of the recipient.
     *
     * <p>The private key is the serialized bytes of the BigInteger returned by {@link
     * ECPrivateKey#getS()}.
     */
    @CanIgnoreReturnValue
    public Builder withRecipientPrivateKey(final byte[] val) throws GeneralSecurityException {
      recipientPrivateKey =
          EllipticCurves.getEcPrivateKey(WebPushConstants.NIST_P256_CURVE_TYPE, val);
      return this;
    }

    public WebPushHybridDecrypt build() throws GeneralSecurityException {
      return new WebPushHybridDecrypt(this);
    }
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] contextInfo /* unused */)
      throws GeneralSecurityException {
    if (contextInfo != null) {
      throw new GeneralSecurityException("contextInfo must be null because it is unused");
    }

    if (ciphertext.length < WebPushConstants.CIPHERTEXT_OVERHEAD) {
      throw new GeneralSecurityException("ciphertext too short");
    }

    // A push service is not required to support more than 4096 octets of
    // payload body. See https://tools.ietf.org/html/rfc8291#section-4.0.
    if (ciphertext.length > WebPushConstants.MAX_CIPHERTEXT_SIZE) {
      throw new GeneralSecurityException("ciphertext too long");
    }

    // Unpacking.
    ByteBuffer record = ByteBuffer.wrap(ciphertext);
    byte[] salt = new byte[WebPushConstants.SALT_SIZE];
    record.get(salt);

    int recordSize = record.getInt();
    if (recordSize != this.recordSize
        || recordSize < ciphertext.length
        || recordSize > WebPushConstants.MAX_CIPHERTEXT_SIZE) {
      throw new GeneralSecurityException("invalid record size: " + recordSize);
    }

    int publicKeySize = (int) record.get();
    if (publicKeySize != WebPushConstants.PUBLIC_KEY_SIZE) {
      throw new GeneralSecurityException("invalid ephemeral public key size: " + publicKeySize);
    }

    byte[] asPublicKey = new byte[WebPushConstants.PUBLIC_KEY_SIZE];
    record.get(asPublicKey);
    ECPoint asPublicPoint =
        EllipticCurves.pointDecode(
            WebPushConstants.NIST_P256_CURVE_TYPE,
            WebPushConstants.UNCOMPRESSED_POINT_FORMAT,
            asPublicKey);

    byte[] payload = new byte[ciphertext.length - WebPushConstants.CONTENT_CODING_HEADER_SIZE];
    record.get(payload);

    // See https://tools.ietf.org/html/rfc8291#section-3.4.
    byte[] ecdhSecret = EllipticCurves.computeSharedSecret(recipientPrivateKey, asPublicPoint);
    byte[] ikm = WebPushUtil.computeIkm(ecdhSecret, authSecret, recipientPublicKey, asPublicKey);
    byte[] cek = WebPushUtil.computeCek(ikm, salt);
    byte[] nonce = WebPushUtil.computeNonce(ikm, salt);

    return decrypt(cek, nonce, payload);
  }

  private byte[] decrypt(final byte[] key, final byte[] nonce, final byte[] ciphertext)
      throws GeneralSecurityException {
    Cipher cipher = EngineFactory.CIPHER.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec params = new GCMParameterSpec(8 * WebPushConstants.TAG_SIZE, nonce);
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), params);
    byte[] plaintext = cipher.doFinal(ciphertext);
    if (plaintext.length == 0) {
      throw new GeneralSecurityException("decryption failed");
    }
    // Remove zero paddings.
    int index = plaintext.length - 1;
    while (index > 0) {
      if (plaintext[index] != 0) {
        break;
      }
      index--;
    }

    if (plaintext[index] != WebPushConstants.PADDING_DELIMITER_BYTE) {
      throw new GeneralSecurityException("decryption failed");
    }
    return Arrays.copyOf(plaintext, index);
  }
}
