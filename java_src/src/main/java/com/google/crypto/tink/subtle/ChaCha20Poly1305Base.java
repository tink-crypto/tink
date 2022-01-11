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
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import javax.crypto.AEADBadTagException;

/**
 * Abstract base class for class of ChaCha20Poly1305 and XChaCha20Poly1305, following RFC 8439
 * https://tools.ietf.org/html/rfc8439.
 *
 * <p>This implementation produces ciphertext with the following format: {@code nonce ||
 * actual_ciphertext || tag} and only decrypts the same format.
 *
 * @deprecated replaced by {@link
 *     com.google.crypto.tink.aead.internal.InsecureNonceChaCha20Poly1305Base}.
 */
@Deprecated
abstract class ChaCha20Poly1305Base implements Aead {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  private final ChaCha20Base chacha20;
  private final ChaCha20Base macKeyChaCha20;

  public ChaCha20Poly1305Base(final byte[] key)
      throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException("Can not use ChaCha20Poly1305 in FIPS-mode.");
    }

    this.chacha20 = newChaCha20Instance(key, 1);
    this.macKeyChaCha20 = newChaCha20Instance(key, 0);
  }

  abstract ChaCha20Base newChaCha20Instance(final byte[] key, int initialCounter)
      throws InvalidKeyException;

  /**
   * Encrypts the {@code plaintext} with Poly1305 authentication based on {@code associatedData}.
   *
   * <p>Please note that nonce is randomly generated hence keys need to be rotated after encrypting
   * a certain number of messages depending on the nonce size of the underlying {@link
   * ChaCha20Base}.
   *
   * @param plaintext data to encrypt
   * @param associatedData associated authenticated data
   * @return ciphertext with the following format {@code nonce || actual_ciphertext || tag}
   */
  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (plaintext.length
        > Integer.MAX_VALUE - chacha20.nonceSizeInBytes() - MAC_TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("plaintext too long");
    }
    ByteBuffer ciphertext =
        ByteBuffer.allocate(plaintext.length + chacha20.nonceSizeInBytes() + MAC_TAG_SIZE_IN_BYTES);

    encrypt(ciphertext, plaintext, associatedData);
    return ciphertext.array();
  }

  private void encrypt(ByteBuffer output, final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (output.remaining()
        < plaintext.length + chacha20.nonceSizeInBytes() + MAC_TAG_SIZE_IN_BYTES) {
      throw new IllegalArgumentException("Given ByteBuffer output is too small");
    }
    int firstPosition = output.position();
    chacha20.encrypt(output, plaintext);
    output.position(firstPosition);
    byte[] nonce = new byte[chacha20.nonceSizeInBytes()];
    output.get(nonce);
    output.limit(output.limit() - MAC_TAG_SIZE_IN_BYTES);
    byte[] aad = associatedData;
    if (aad == null) {
      aad = new byte[0];
    }
    byte[] tag = Poly1305.computeMac(getMacKey(nonce), macDataRfc8439(aad, output));
    output.limit(output.limit() + MAC_TAG_SIZE_IN_BYTES);
    output.put(tag);
  }

  /**
   * Decryptes {@code ciphertext} with the following format: {@code nonce || actual_ciphertext ||
   * tag}
   *
   * @param ciphertext with format {@code nonce || actual_ciphertext || tag}
   * @param associatedData associated authenticated data
   * @return plaintext if authentication is successful.
   * @throws GeneralSecurityException when ciphertext is shorter than nonce size + tag size or when
   *     computed tag based on {@code ciphertext} and {@code associatedData} does not match the tag
   *     given in {@code ciphertext}.
   */
  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    return decrypt(ByteBuffer.wrap(ciphertext), associatedData);
  }

  /**
   * Decryptes {@code ciphertext} with the following format: {@code nonce || actual_ciphertext ||
   * tag}
   *
   * @param ciphertext with format {@code nonce || actual_ciphertext || tag}
   * @param associatedData associated authenticated data
   * @return plaintext if authentication is successful
   * @throws GeneralSecurityException when ciphertext is shorter than nonce size + tag size
   * @throws AEADBadTagException when the tag is invalid
   */
  private byte[] decrypt(ByteBuffer ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (ciphertext.remaining() < chacha20.nonceSizeInBytes() + MAC_TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    int firstPosition = ciphertext.position();
    byte[] tag = new byte[MAC_TAG_SIZE_IN_BYTES];
    ciphertext.position(ciphertext.limit() - MAC_TAG_SIZE_IN_BYTES);
    ciphertext.get(tag);
    // rewind to read ciphertext and compute tag.
    ciphertext.position(firstPosition);
    ciphertext.limit(ciphertext.limit() - MAC_TAG_SIZE_IN_BYTES);
    byte[] nonce = new byte[chacha20.nonceSizeInBytes()];
    ciphertext.get(nonce);
    byte[] aad = associatedData;
    if (aad == null) {
      aad = new byte[0];
    }
    try {
      Poly1305.verifyMac(getMacKey(nonce), macDataRfc8439(aad, ciphertext), tag);
    } catch (GeneralSecurityException ex) {
      throw new AEADBadTagException(ex.toString());
    }

    // rewind to decrypt the ciphertext.
    ciphertext.position(firstPosition);
    return chacha20.decrypt(ciphertext);
  }

  /** The MAC key is the first 32 bytes of the first key stream block */
  private byte[] getMacKey(final byte[] nonce) throws GeneralSecurityException {
    ByteBuffer firstBlock = macKeyChaCha20.chacha20Block(nonce, 0 /* counter */);
    byte[] result = new byte[MAC_KEY_SIZE_IN_BYTES];
    firstBlock.get(result);
    return result;
  }

  /** Prepares the input to MAC, following RFC 8439, section 2.8. */
  private static byte[] macDataRfc8439(final byte[] aad, ByteBuffer ciphertext) {
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
}
