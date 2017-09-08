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

import static com.google.crypto.tink.subtle.Poly1305.MAC_TAG_SIZE_IN_BYTES;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.annotations.Alpha;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;

/**
 * an {@code Aead} construction with a {@link DjbCipher} and Poly1305.
 *
 * <p>Supported DjbCiphers are documented in the static construct methods. Although the algorithms
 * are the same with their counterparts when stated explicitly (wrt. NaCl, libsodium, or RFC 7539),
 * this implementation of Poly1305 produces ciphertext with the following format: <br>
 * {@code nonce || actual_ciphertext || tag} and only decrypts the same format. In NaCl and
 * libsodium, messages to be encrypted are required to be padded with 0 for tag byte length and also
 * decryption produces messages that are 0 padded in XSalsa20Poly1305.(though please note that
 * libsodium does not require it for XChaCha20Poly1305 but still uses this trick under the hood to
 * reuse ChaCha20 library) Subkey for Poly1305 is populated to these 0 values during the encryption
 * and it is overwritten with the tag value when Poly1305 is computed. Although this is a
 * convenience (and also efficient in C) wrt implementation, it makes the API harder to use. Thus,
 * this implementation chooses not to support the NaCl and libsodium's ciphertext format, instead
 * put the tag at the end to be consistent with other AEAD's in this library.
 *
 * <p>The implementation is based on poly1305 implementation by Andrew Moon
 * (https://github.com/floodyberry/poly1305-donna) and released as public domain.
 */
@Alpha
public abstract class DjbCipherPoly1305 implements Aead {

  private final DjbCipher djbCipher;

  private DjbCipherPoly1305(DjbCipher djbCipher) {
    this.djbCipher = djbCipher;
  }

  /**
   * Based on <a href="https://tools.ietf.org/html/rfc7539#section-2.8">RFC 7539, section 2.8</a>.
   */
  private static class DjbCipherPoly1305Ietf extends DjbCipherPoly1305 {

    private DjbCipherPoly1305Ietf(DjbCipher djbCipher) {
      super(djbCipher);
    }

    @Override
    byte[] macData(byte[] aad, ByteBuffer ciphertext) {
      int aadCeilLen = blockSizeMultipleCeil(aad.length);
      int ciphertextLen = ciphertext.remaining();
      int ciphertextCeilLen = blockSizeMultipleCeil(ciphertextLen);
      ByteBuffer macData =
          ByteBuffer.allocate(aadCeilLen + ciphertextCeilLen + 16).order(ByteOrder.LITTLE_ENDIAN);
      macData.put(aad);
      macData.position(aadCeilLen);
      macData.put(ciphertext);
      macData.position(aadCeilLen + ciphertextCeilLen);
      macData.putLong(aad.length);
      macData.putLong(ciphertextLen);
      return macData.array();
    }
  }

  /** DJB's NaCl box compatible Poly1305. */
  private static class DjbCipherPoly1305Nacl extends DjbCipherPoly1305 {

    private DjbCipherPoly1305Nacl(DjbCipher djbCipher) {
      super(djbCipher);
    }

    @Override
    byte[] macData(byte[] aad, ByteBuffer ciphertext) {
      byte[] macData = new byte[ciphertext.remaining()];
      ciphertext.get(macData);
      return macData;
    }
  }

  /**
   * Constructs a new ChaCha20Poly1305 cipher with the supplied {@code key}. Compatible with RFC
   * 7539.
   *
   * @throws IllegalArgumentException when {@code key} length is not {@link
   *     DjbCipher#KEY_SIZE_IN_BYTES}.
   */
  public static DjbCipherPoly1305 constructChaCha20Poly1305Ietf(final byte[] key) {
    return new DjbCipherPoly1305Ietf(DjbCipher.chaCha20(key));
  }

  /**
   * Constructs a new NaCl compatible XSalsa20Poly1305 cipher with the supplied {@code key}.
   *
   * @throws IllegalArgumentException when {@code key} length is not {@link
   *     DjbCipher#KEY_SIZE_IN_BYTES}.
   */
  public static DjbCipherPoly1305 constructXSalsa20Poly1305Nacl(final byte[] key) {
    return new DjbCipherPoly1305Nacl(DjbCipher.xSalsa20(key));
  }

  /**
   * Constructs a new libsodium compatible XChaCha20Poly1305 cipher with the supplied {@code key}.
   * Compatible with libsodium/crypto_aead/xchacha20poly1305/sodium/aead_xchacha20poly1305.c
   *
   * @throws IllegalArgumentException when {@code key} length is not {@link
   *     DjbCipher#KEY_SIZE_IN_BYTES}.
   */
  public static DjbCipherPoly1305 constructXChaCha20Poly1305Ietf(final byte[] key) {
    return new DjbCipherPoly1305Ietf(DjbCipher.xChaCha20(key));
  }

  private static int blockSizeMultipleCeil(int x) {
    return ((x + MAC_TAG_SIZE_IN_BYTES - 1) / MAC_TAG_SIZE_IN_BYTES) * MAC_TAG_SIZE_IN_BYTES;
  }

  abstract byte[] macData(byte[] aad, ByteBuffer ciphertext);

  public int nonceSizeInBytes() {
    return djbCipher.nonceSizeInBytes();
  }

  /**
   * Encrypts the {@code plaintext} with Poly1305 authentication based on {@code additionalData}.
   *
   * <p>Please note that nonce is randomly generated hence keys need to be rotated after encrypting
   * a certain number of messages depending on the nonce size of the underlying {@link DjbCipher}.
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
    ByteBuffer ciphertext =
        ByteBuffer.allocate(nonceSizeInBytes() + plaintext.length + MAC_TAG_SIZE_IN_BYTES);
    encrypt(ciphertext, plaintext, additionalData);
    return ciphertext.array();
  }

  void encrypt(ByteBuffer output, final byte[] plaintext, final byte[] additionalData)
      throws GeneralSecurityException {
    if (output.remaining() < plaintext.length + nonceSizeInBytes() + MAC_TAG_SIZE_IN_BYTES) {
      throw new IllegalArgumentException("Given ByteBuffer output is too small");
    }
    int firstPosition = output.position();
    djbCipher.encrypt(output, plaintext);
    output.position(firstPosition);
    byte[] nonce = new byte[djbCipher.nonceSizeInBytes()];
    output.get(nonce);
    output.limit(output.limit() - MAC_TAG_SIZE_IN_BYTES);
    byte[] tag =
        Poly1305.computeMac(djbCipher.getAuthenticatorKey(nonce), macData(additionalData, output));
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
   * @return plaintext if authentication is successful.
   * @throws GeneralSecurityException when ciphertext is shorter than nonce size + tag size or when
   *     computed tag based on {@code ciphertext} and {@code additionalData} does not match the tag
   *     given in {@code ciphertext}.
   */
  byte[] decrypt(ByteBuffer ciphertext, final byte[] additionalData)
      throws GeneralSecurityException {
    if (ciphertext.remaining() < djbCipher.nonceSizeInBytes() + MAC_TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    int firstPosition = ciphertext.position();
    byte[] tag = new byte[MAC_TAG_SIZE_IN_BYTES];
    ciphertext.position(ciphertext.limit() - MAC_TAG_SIZE_IN_BYTES);
    ciphertext.get(tag);
    // rewind to read ciphertext and compute tag.
    ciphertext.position(firstPosition);
    ciphertext.limit(ciphertext.limit() - MAC_TAG_SIZE_IN_BYTES);
    byte[] nonce = new byte[djbCipher.nonceSizeInBytes()];
    ciphertext.get(nonce);
    Poly1305.verifyMac(
        djbCipher.getAuthenticatorKey(nonce), macData(additionalData, ciphertext), tag);
    // rewind to decrypt the ciphertext.
    ciphertext.position(firstPosition);
    return djbCipher.decrypt(ciphertext);
  }
}
