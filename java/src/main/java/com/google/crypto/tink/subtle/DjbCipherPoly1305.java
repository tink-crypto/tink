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

import static com.google.crypto.tink.subtle.DjbCipher.KEY_SIZE_IN_BYTES;

import com.google.crypto.tink.Aead;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * an {@code Aead} construction with a {@link DjbCipher} and Poly1305.
 *
 * Supported DjbCiphers are documented in the static construct methods. Although the algorithms
 * are the same with their counterparts when stated explicitly (wrt. NaCl, libsodium, or RFC 7539),
 * this implementation of Poly1305 produces ciphertext with the following format:
 *   <br>{@code nonce || actual_ciphertext || tag}
 * and only decrypts the same format.
 * In NaCl and libsodium, messages to be encrypted are required to be padded with 0 for tag byte
 * length and also decryption produces messages that are 0 padded in XSalsa20Poly1305.(though please
 * note that libsodium does not require it for XChaCha20Poly1305 but still uses this trick under the
 * hood to reuse ChaCha20 library)  Subkey for Poly1305 is populated to these 0 values during the
 * encryption and it is overwritten with the tag value when Poly1305 is computed. Although this is a
 * convenience (and also efficient in C) wrt implementation, it makes the API harder to use. Thus,
 * this implementation chooses not to support the NaCl and libsodium's ciphertext format, instead
 * put the tag at the end to be consistent with other AEAD's in this library.
 *
 * The implementation is based on poly1305 implementation by Andrew Moon
 * (https://github.com/floodyberry/poly1305-donna) and released as public domain.
 */
public abstract class DjbCipherPoly1305 implements Aead {

  public static final int MAC_TAG_SIZE_IN_BYTES = 16;
  public static final int MAC_KEY_SIZE_IN_BYTES = 32;

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
    byte[] macData(byte[] aad, ByteBuffer ciphertext)  {
      int aadCeilLen = blockSizeMultipleCeil(aad.length);
      int ciphertextLen = ciphertext.remaining();
      int ciphertextCeilLen = blockSizeMultipleCeil(ciphertextLen);
      ByteBuffer macData = ByteBuffer.allocate(
          aadCeilLen + ciphertextCeilLen + 16).order(ByteOrder.LITTLE_ENDIAN);
      macData.put(aad);
      macData.position(aadCeilLen);
      macData.put(ciphertext);
      macData.position(aadCeilLen + ciphertextCeilLen);
      macData.putLong(aad.length);
      macData.putLong(ciphertextLen);
      return macData.array();
    }
  }

  /**
   * DJB's NaCl box compatible Poly1305.
   */
  private static class DjbCipherPoly1305Nacl extends DjbCipherPoly1305 {

    private DjbCipherPoly1305Nacl(DjbCipher djbCipher) {
      super(djbCipher);
    }

    @Override
    byte[] macData(byte[] aad, ByteBuffer ciphertext)  {
      byte[] macData = new byte[ciphertext.remaining()];
      ciphertext.get(macData);
      return macData;
    }
  }

  /**
   * Constructs a new ChaCha20Poly1305 cipher with the supplied {@code key}. Compatible with
   * RFC 7539.
   *
   * @throws IllegalArgumentException when {@code key} length is not
   * {@link DjbCipher#KEY_SIZE_IN_BYTES}.
   */
  public static DjbCipherPoly1305 constructChaCha20Poly1305Ietf(final byte[] key) {
    return new DjbCipherPoly1305Ietf(DjbCipher.chaCha20(key));
  }

  /**
   * Constructs a new NaCl compatible XSalsa20Poly1305 cipher with the supplied {@code key}.
   *
   * @throws IllegalArgumentException when {@code key} length is not
   * {@link DjbCipher#KEY_SIZE_IN_BYTES}.
   */
  public static DjbCipherPoly1305 constructXSalsa20Poly1305Nacl(final byte[] key) {
    return new DjbCipherPoly1305Nacl(DjbCipher.xSalsa20(key));
  }

  /**
   * Constructs a new libsodium compatible XChaCha20Poly1305 cipher with the supplied {@code key}.
   *
   * @throws IllegalArgumentException when {@code key} length is not
   * {@link DjbCipher#KEY_SIZE_IN_BYTES}.
   */
  public static DjbCipherPoly1305 constructXChaCha20Poly1305Nacl(final byte[] key) {
    return new DjbCipherPoly1305Nacl(DjbCipher.xChaCha20(key));
  }

  private static long load32(byte[] in, int idx) {
    return ((in[idx] & 0xff)
        | ((in[idx + 1] & 0xff) << 8)
        | ((in[idx + 2] & 0xff) << 16)
        | ((in[idx + 3] & 0xff) << 24)) & 0xffffffffL;
  }

  private static long load26(byte[] in, int idx, int shift) {
    return (load32(in, idx) >> shift) & 0x3ffffff;
  }

  private static void toByteArray(byte[] output, long num, int idx) {
    for (int i = 0; i < 4; i++, num >>= 8) {
      output[idx + i] = (byte) (num & 0xff);
    }
  }

  private static void copyBlockSize(byte[] output, byte[] in, int idx) {
    int copyCount = Math.min(MAC_TAG_SIZE_IN_BYTES, in.length - idx);
    System.arraycopy(in, idx, output, 0, copyCount);
    output[copyCount] = 1;
    if (copyCount != MAC_TAG_SIZE_IN_BYTES) {
      Arrays.fill(output, copyCount + 1, output.length, (byte) 0);
    }
  }

  // Package private for testing
  static byte[] poly1305Mac(byte[] msg, byte[] key) {
    if (key.length < KEY_SIZE_IN_BYTES) {
      throw new IllegalArgumentException("The key length in bytes must be 32.");
    }
    long h0 = 0;
    long h1 = 0;
    long h2 = 0;
    long h3 = 0;
    long h4 = 0;
    long d0;
    long d1;
    long d2;
    long d3;
    long d4;
    long c;

    // r &= 0xffffffc0ffffffc0ffffffc0fffffff
    long r0 = load26(key, 0, 0) & 0x3ffffff;
    long r1 = load26(key, 3, 2) & 0x3ffff03;
    long r2 = load26(key, 6, 4) & 0x3ffc0ff;
    long r3 = load26(key, 9, 6) & 0x3f03fff;
    long r4 = load26(key, 12, 8) & 0x00fffff;

    long s1 = r1 * 5;
    long s2 = r2 * 5;
    long s3 = r3 * 5;
    long s4 = r4 * 5;

    byte[] buf = new byte[MAC_TAG_SIZE_IN_BYTES + 1];
    for (int i = 0; i < msg.length; i += MAC_TAG_SIZE_IN_BYTES) {
      copyBlockSize(buf, msg, i);
      h0 += load26(buf, 0, 0);
      h1 += load26(buf, 3, 2);
      h2 += load26(buf, 6, 4);
      h3 += load26(buf, 9, 6);
      h4 += load26(buf, 12, 8) | (buf[MAC_TAG_SIZE_IN_BYTES] << 24);

      // d = r * h
      d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
      d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
      d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
      d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
      d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

      // Partial reduction mod 2^130-5, resulting h1 might not be 26bits.
      c = d0 >> 26; h0 = d0 & 0x3ffffff; d1 += c;
      c = d1 >> 26; h1 = d1 & 0x3ffffff; d2 += c;
      c = d2 >> 26; h2 = d2 & 0x3ffffff; d3 += c;
      c = d3 >> 26; h3 = d3 & 0x3ffffff; d4 += c;
      c = d4 >> 26; h4 = d4 & 0x3ffffff; h0 += c * 5;
      c = h0 >> 26; h0 = h0 & 0x3ffffff; h1 += c;
    }
    // Do final reduction mod 2^130-5
    c = h1 >> 26; h1 = h1 & 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 = h2 & 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 = h3 & 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 = h4 & 0x3ffffff; h0 += c * 5;  // c * 5 can be at most 5
    c = h0 >> 26; h0 = h0 & 0x3ffffff; h1 += c;

    // Compute h - p
    long g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    long g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    long g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    long g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    long g4 = h4 + c - (1 << 26);

    // Select h if h < p, or h - p if h >= p
    long mask = g4 >> 63;  // mask is either 0 (h >= p) or -1 (h < p)
    h0 &= mask;
    h1 &= mask;
    h2 &= mask;
    h3 &= mask;
    h4 &= mask;
    mask = ~mask;
    h0 |= g0 & mask;
    h1 |= g1 & mask;
    h2 |= g2 & mask;
    h3 |= g3 & mask;
    h4 |= g4 & mask;

    // h = h % (2^128)
    h0 = (h0 | (h1 << 26)) & 0xffffffffL;
    h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffffL;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffffL;
    h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffffL;

    // mac = (h + pad) % (2^128)
    c = h0 + load32(key, 16); h0 = c & 0xffffffffL;
    c = h1 + load32(key, 20) + (c >> 32); h1 = c & 0xffffffffL;
    c = h2 + load32(key, 24) + (c >> 32); h2 = c & 0xffffffffL;
    c = h3 + load32(key, 28) + (c >> 32); h3 = c & 0xffffffffL;

    byte[] mac = new byte[MAC_TAG_SIZE_IN_BYTES];
    toByteArray(mac, h0, 0);
    toByteArray(mac, h1, 4);
    toByteArray(mac, h2, 8);
    toByteArray(mac, h3, 12);

    return mac;
  }

  private static int blockSizeMultipleCeil(int x) {
    return ((x + MAC_TAG_SIZE_IN_BYTES - 1) / MAC_TAG_SIZE_IN_BYTES) * MAC_TAG_SIZE_IN_BYTES;
  }

  abstract byte[] macData(byte[] aad, ByteBuffer ciphertext);

  private byte[] computeTag(ByteBuffer ciphertextBuf, byte[] additionalData, byte[] aeadSubKey) {
    return poly1305Mac(macData(additionalData, ciphertextBuf), aeadSubKey);
  }

  public int nonceSizeInBytes() {
    return djbCipher.nonceSizeInBytes();
  }

  /**
   * Encrypts the {@code plaintext} with Poly1305 authentication based on {@code additionalData}.
   *
   * Please note that nonce is randomly generated hence keys need to be rotated after encrypting
   * a certain number of messages depending on the nonce size of the underlying {@link DjbCipher}.
   * Reference:
   * Using 96-bit random nonces, it is possible to encrypt, with a single key, up to 2^32 messages
   * with probability of collision <= 2^-32
   * whereas using 192-bit random nonces, the number of messages that can be encrypted with the same
   * key is up to 2^80 with the same probability of collusion.
   *
   * @param plaintext data to encrypt
   * @param additionalData additional data
   * @return ciphertext with the following format {@code nonce || actual_ciphertext || tag}
   */
  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] additionalData)
      throws GeneralSecurityException {
    byte[] ciphertext = djbCipher.encrypt(plaintext);
    ByteBuffer ciphertextBuf = ByteBuffer.wrap(ciphertext);
    byte[] nonce = new byte[djbCipher.nonceSizeInBytes()];
    ciphertextBuf.get(nonce);
    byte[] aeadSubKey = djbCipher.getAuthenticatorKey(nonce);
    byte[] tag = computeTag(ciphertextBuf, additionalData, aeadSubKey);
    ByteBuffer ciphertextWithTag = ByteBuffer.allocate(ciphertext.length + tag.length);
    ciphertextWithTag.put(ciphertext);
    ciphertextWithTag.put(tag);
    return ciphertextWithTag.array();
  }

  /**
   * Decryptes {@code ciphertext} with the following format:
   * {@code nonce || actual_ciphertext || tag}
   *
   * @param ciphertext with format {@code nonce || actual_ciphertext || tag}
   * @param additionalData additional data
   * @return plaintext if authentication is successful.
   * @throws GeneralSecurityException when ciphertext is shorter than nonce size + tag size
   *  or when computed tag based on {@code ciphertext} and {@code additionalData} does not match
   *  the tag given in {@code ciphertext}.
   */
  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] additionalData)
      throws GeneralSecurityException {
    if (ciphertext.length < djbCipher.nonceSizeInBytes() + MAC_TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    byte[] tag = new byte[MAC_TAG_SIZE_IN_BYTES];
    System.arraycopy(
        ciphertext, ciphertext.length - MAC_TAG_SIZE_IN_BYTES, tag, 0, MAC_TAG_SIZE_IN_BYTES);
    ByteBuffer ciphertextBuf = ByteBuffer.wrap(
        ciphertext, 0, ciphertext.length - MAC_TAG_SIZE_IN_BYTES);
    byte[] nonce = new byte[djbCipher.nonceSizeInBytes()];
    ciphertextBuf.get(nonce);
    byte[] expectedTag =
        computeTag(ciphertextBuf, additionalData, djbCipher.getAuthenticatorKey(nonce));
    if (!SubtleUtil.arrayEquals(tag, expectedTag)) {
      throw new GeneralSecurityException("Tags do not match.");
    }
    ciphertextBuf.rewind();
    return djbCipher.decrypt(ciphertextBuf);
  }
}
