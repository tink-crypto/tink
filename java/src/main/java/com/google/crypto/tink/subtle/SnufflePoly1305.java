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

package com.google.crypto.tink.subtle;

import static com.google.crypto.tink.subtle.Poly1305.MAC_KEY_SIZE_IN_BYTES;
import static com.google.crypto.tink.subtle.Poly1305.MAC_TAG_SIZE_IN_BYTES;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.annotations.Alpha;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import javax.crypto.AEADBadTagException;

/**
 * An {@link Aead} construction with a {@link com.google.crypto.tink.subtle.Snuffle} and {@link
 * com.google.crypto.tink.subtle.Poly1305}, following RFC 7539, section 2.8.
 *
 * <p>This implementation produces ciphertext with the following format: {@code nonce ||
 * actual_ciphertext || tag} and only decrypts the same format.
 */
@Alpha
abstract class SnufflePoly1305 implements Aead {
  private final byte[] key;
  private final Snuffle snuffle;
  private final Snuffle macKeysnuffle;

  SnufflePoly1305(final byte[] key) throws InvalidKeyException {
    this.key = key.clone();
    this.snuffle = createSnuffleInstance(key, 1);
    this.macKeysnuffle = createSnuffleInstance(key, 0);
  }

  abstract Snuffle createSnuffleInstance(final byte[] key, int initialCounter)
      throws InvalidKeyException;

  /**
   * Encrypts the {@code plaintext} with Poly1305 authentication based on {@code additionalData}.
   *
   * <p>Please note that nonce is randomly generated hence keys need to be rotated after encrypting
   * a certain number of messages depending on the nonce size of the underlying {@link Snuffle}.
   * Reference: Using 96-bit random nonces, it is possible to encrypt, with a single key, up to 2^32
   * messages with probability of collision <= 2^-32 whereas using 192-bit random nonces, the number
   * of messages that can be encrypted with the same key is up to 2^80 with the same probability of
   * collusion.
   *
   * @param plaintext data to encrypt
   * @param additionalData additional data
   * @return ciphertext with the following format {@code nonce || actual_ciphertext || tag}
   */
  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] additionalData)
      throws GeneralSecurityException {
    if (plaintext.length > Integer.MAX_VALUE - snuffle.nonceSizeInBytes() - MAC_TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("plaintext too long");
    }
    ByteBuffer ciphertext =
        ByteBuffer.allocate(plaintext.length + snuffle.nonceSizeInBytes() + MAC_TAG_SIZE_IN_BYTES);

    encrypt(ciphertext, plaintext, additionalData);
    return ciphertext.array();
  }

  private void encrypt(ByteBuffer output, final byte[] plaintext, final byte[] additionalData)
      throws GeneralSecurityException {
    if (output.remaining()
        < plaintext.length + snuffle.nonceSizeInBytes() + MAC_TAG_SIZE_IN_BYTES) {
      throw new IllegalArgumentException("Given ByteBuffer output is too small");
    }
    int firstPosition = output.position();
    snuffle.encrypt(output, plaintext);
    output.position(firstPosition);
    byte[] nonce = new byte[snuffle.nonceSizeInBytes()];
    output.get(nonce);
    output.limit(output.limit() - MAC_TAG_SIZE_IN_BYTES);
    byte[] tag = Poly1305.computeMac(getMacKey(nonce), macDataRfc7539(additionalData, output));
    output.limit(output.limit() + MAC_TAG_SIZE_IN_BYTES);
    output.put(tag);
  }

  /**
   * Decryptes {@code ciphertext} with the following format: {@code nonce || actual_ciphertext ||
   * tag}
   *
   * @param ciphertext with format {@code nonce || actual_ciphertext || tag}
   * @param additionalData additional data
   * @return plaintext if authentication is successful.
   * @throws GeneralSecurityException when ciphertext is shorter than nonce size + tag size or when
   *     computed tag based on {@code ciphertext} and {@code additionalData} does not match the tag
   *     given in {@code ciphertext}.
   */
  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] additionalData)
      throws GeneralSecurityException {
    return decrypt(ByteBuffer.wrap(ciphertext), additionalData);
  }

  /**
   * Decryptes {@code ciphertext} with the following format: {@code nonce || actual_ciphertext ||
   * tag}
   *
   * @param ciphertext with format {@code nonce || actual_ciphertext || tag}
   * @param additionalData additional data
   * @return plaintext if authentication is successful
   * @throws GeneralSecurityException when ciphertext is shorter than nonce size + tag size
   * @throws AEADBadTagException when the tag is invalid
   */
  private byte[] decrypt(ByteBuffer ciphertext, final byte[] additionalData)
      throws GeneralSecurityException {
    if (ciphertext.remaining() < snuffle.nonceSizeInBytes() + MAC_TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    int firstPosition = ciphertext.position();
    byte[] tag = new byte[MAC_TAG_SIZE_IN_BYTES];
    ciphertext.position(ciphertext.limit() - MAC_TAG_SIZE_IN_BYTES);
    ciphertext.get(tag);
    // rewind to read ciphertext and compute tag.
    ciphertext.position(firstPosition);
    ciphertext.limit(ciphertext.limit() - MAC_TAG_SIZE_IN_BYTES);
    byte[] nonce = new byte[snuffle.nonceSizeInBytes()];
    ciphertext.get(nonce);
    try {
      Poly1305.verifyMac(getMacKey(nonce), macDataRfc7539(additionalData, ciphertext), tag);
    } catch (GeneralSecurityException ex) {
      throw new AEADBadTagException(ex.toString());
    }

    // rewind to decrypt the ciphertext.
    ciphertext.position(firstPosition);
    return snuffle.decrypt(ciphertext);
  }

  /** Prepares the input to MAC, following RFC 7539, section 2.8. */
  static byte[] macDataRfc7539(final byte[] aad, ByteBuffer ciphertext) {
    int aadPaddedLen = (aad.length % 16 == 0) ? aad.length : (aad.length + 16 - aad.length % 16);
    int ciphertextLen = ciphertext.remaining();
    int ciphertextPaddedLen =
        (ciphertextLen % 16 == 0) ? ciphertextLen : (ciphertextLen + 16 - ciphertextLen % 16);
    ByteBuffer macData =
        ByteBuffer.allocate(aadPaddedLen + ciphertextPaddedLen + 16).order(ByteOrder.LITTLE_ENDIAN);
    macData.put(aad);
    macData.position(aadPaddedLen);
    macData.put(ciphertext);
    macData.position(aadPaddedLen + ciphertextPaddedLen);
    macData.putLong(aad.length);
    macData.putLong(ciphertextLen);
    return macData.array();
  }

  /** The MAC key is the first 32 bytes of the first key stream block */
  private byte[] getMacKey(final byte[] nonce) throws InvalidKeyException {
    ByteBuffer firstBlock = macKeysnuffle.getKeyStreamBlock(nonce, 0 /* counter */);
    byte[] result = new byte[MAC_KEY_SIZE_IN_BYTES];
    firstBlock.get(result);
    return result;
  }
}
