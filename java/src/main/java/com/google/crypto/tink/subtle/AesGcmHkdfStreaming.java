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

import com.google.crypto.tink.annotations.Alpha;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Streaming encryption using AES-GCM with HKDF as key derivation function.
 *
 * <p>Each ciphertext uses a new AES-GCM key that is derived from the key derivation key, a randomly
 * chosen salt of the same size as the key and a nonce prefix.
 *
 * <p>The the format of a ciphertext is header || segment_0 || segment_1 || ... || segment_k. The
 * header has size this.getHeaderLength(). Its format is headerLength || salt || prefix. where
 * headerLength is 1 byte determining the size of the header, salt is a salt used in the key
 * derivation and prefix is the prefix of the nonce. In principle headerLength is redundant
 * information, since the length of the header can be determined from the key size.
 *
 * <p>segment_i is the i-th segment of the ciphertext. The size of segment_1 .. segment_{k-1} is
 * ciphertextSegmentSize. segment_0 is shorter, so that segment_0, the header and other information
 * of size firstSegmentOffset align with ciphertextSegmentSize.
 */
@Alpha
public final class AesGcmHkdfStreaming extends NonceBasedStreamingAead {
  // TODO(bleichen): Some things that are not yet decided:
  //   - What can we assume about the state of objects after getting an exception?
  //   - Should there be a simple test to detect invalid ciphertext offsets?
  //   - Should we encode the size of the header?
  //   - Should we encode the size of the segments?
  //   - Should a version be included in the header to allow header modification?
  //   - Should we allow other information, header and the first segment the to be a multiple of
  //     ciphertextSegmentSize?
  //   - This implementation fixes a number of parameters. Should there be more options?
  //   - Should we authenticate ciphertextSegmentSize and firstSegmentSize?
  //     If an attacker can change these parameters then this would allow to move
  //     the position of plaintext in the file. While these parameters are currently
  //     specified by the key it is unclear whether this will remain so in the future.
  //
  // The size of the IVs for GCM
  private static final int NONCE_SIZE_IN_BYTES = 12;

  // The nonce has the format nonce_prefix || ctr || last_block
  // The nonce_prefix is constant for the whole file.
  // The ctr is a 32 bit ctr, the last_block is 1 if this is the
  // last block of the file and 0 otherwise.
  private static final int NONCE_PREFIX_IN_BYTES = 7;

  // The size of the tags of each ciphertext segment.
  private static final int TAG_SIZE_IN_BYTES = 16;

  // The MAC algorithm used for the key derivation
  private static final String MAC_ALGORITHM = "HMACSHA256";

  private int keySizeInBytes;
  private int ciphertextSegmentSize;
  private int plaintextSegmentSize;
  private int firstSegmentOffset;
  private byte[] ikm;

  /**
   * Initializes a streaming primitive with a key derivation key and encryption parameters.
   *
   * @param ikm input keying material used to derive sub keys.
   * @param keySizeInBytes the key size of the sub keys
   * @param ciphertextSegmentSize the size of ciphertext segments.
   * @param firstSegmentOffset the offset of the first ciphertext segment. That means the first
   *     segment has size ciphertextSegmentSize - getHeaderLength() - firstSegmentOffset
   * @throws InvalidAlgorithmParameterException if ikm is too short, the key size not supported or
   *     ciphertextSegmentSize is to short.
   */
  public AesGcmHkdfStreaming(
      byte[] ikm, int keySizeInBytes, int ciphertextSegmentSize, int firstSegmentOffset)
      throws InvalidAlgorithmParameterException {
    // Checks
    if (ikm.length < 16) {
      throw new InvalidAlgorithmParameterException("ikm to short");
    }
    boolean isValidKeySize = keySizeInBytes == 16 || keySizeInBytes == 24 || keySizeInBytes == 32;
    if (!isValidKeySize) {
      throw new InvalidAlgorithmParameterException("Invalid key size");
    }
    if (ciphertextSegmentSize <= firstSegmentOffset + getHeaderLength() + TAG_SIZE_IN_BYTES) {
      throw new InvalidAlgorithmParameterException("ciphertextSegmentSize too small");
    }
    this.ikm = Arrays.copyOf(ikm, ikm.length);
    this.keySizeInBytes = keySizeInBytes;
    this.ciphertextSegmentSize = ciphertextSegmentSize;
    this.firstSegmentOffset = firstSegmentOffset;
    this.plaintextSegmentSize = ciphertextSegmentSize - TAG_SIZE_IN_BYTES;
  }

  @Override
  public AesGcmHkdfStreamEncrypter newStreamSegmentEncrypter(byte[] aad)
      throws GeneralSecurityException {
    return new AesGcmHkdfStreamEncrypter(aad);
  }

  @Override
  public AesGcmHkdfStreamDecrypter newStreamSegmentDecrypter() throws GeneralSecurityException {
    return new AesGcmHkdfStreamDecrypter();
  }

  @Override
  public int getPlaintextSegmentSize() {
    return plaintextSegmentSize;
  }

  @Override
  public int getCiphertextSegmentSize() {
    return ciphertextSegmentSize;
  }

  @Override
  public int getHeaderLength() {
    return 1 + keySizeInBytes + NONCE_PREFIX_IN_BYTES;
  }

  @Override
  public int getCiphertextOffset() {
    return getHeaderLength() + firstSegmentOffset;
  }

  @Override
  public int getCiphertextOverhead() {
    return TAG_SIZE_IN_BYTES;
  }

  public int getFirstSegmentOffset() {
    return firstSegmentOffset;
  }

  /**
   * Returns the expected size of the ciphertext for a given plaintext The returned value includes
   * the header and offset.
   */
  public long expectedCiphertextSize(long plaintextSize) {
    long offset = getCiphertextOffset();
    long fullSegments = (plaintextSize + offset) / plaintextSegmentSize;
    long ciphertextSize = fullSegments * ciphertextSegmentSize;
    long lastSegmentSize = (plaintextSize + offset) % plaintextSegmentSize;
    if (lastSegmentSize > 0) {
      ciphertextSize += lastSegmentSize + TAG_SIZE_IN_BYTES;
    }
    return ciphertextSize;
  }

  private static Cipher cipherInstance() throws GeneralSecurityException {
    return EngineFactory.CIPHER.getInstance("AES/GCM/NoPadding");
  }

  private byte[] randomSalt() {
    return Random.randBytes(keySizeInBytes);
  }

  private GCMParameterSpec paramsForSegment(byte[] prefix, int segmentNr, boolean last) {
    ByteBuffer nonce = ByteBuffer.allocate(NONCE_SIZE_IN_BYTES);
    nonce.order(ByteOrder.BIG_ENDIAN);
    nonce.put(prefix);
    nonce.putInt(segmentNr);
    nonce.put((byte) (last ? 1 : 0));
    return new GCMParameterSpec(8 * TAG_SIZE_IN_BYTES, nonce.array());
  }

  private byte[] randomNonce() {
    return Random.randBytes(NONCE_PREFIX_IN_BYTES);
  }

  private SecretKeySpec deriveKeySpec(byte[] salt, byte[] aad) throws GeneralSecurityException {
    byte[] key = Hkdf.computeHkdf(MAC_ALGORITHM, ikm, salt, aad, keySizeInBytes);
    return new SecretKeySpec(key, "AES");
  }

  /**
   * An instance of a crypter used to encrypt a plaintext stream. The instances have state:
   * encryptedSegments counts the number of encrypted segments. This state is used to generate the
   * IV for each segment. By enforcing that only the method encryptSegment can increment this state,
   * we can guarantee that the IV does not repeat.
   */
  class AesGcmHkdfStreamEncrypter implements StreamSegmentEncrypter {
    private final SecretKeySpec keySpec;
    private final Cipher cipher;
    private final byte[] noncePrefix;
    private ByteBuffer header;
    private int encryptedSegments = 0;

    public AesGcmHkdfStreamEncrypter(byte[] aad) throws GeneralSecurityException {
      cipher = cipherInstance();
      encryptedSegments = 0;
      byte[] salt = randomSalt();
      noncePrefix = randomNonce();
      header = ByteBuffer.allocate(getHeaderLength());
      header.put((byte) getHeaderLength());
      header.put(salt);
      header.put(noncePrefix);
      header.flip();
      keySpec = deriveKeySpec(salt, aad);
    }

    @Override
    public ByteBuffer getHeader() {
      return header.asReadOnlyBuffer();
    }

    /**
     * Encrypts the next plaintext segment. This uses encryptedSegments as the segment number for
     * the encryption.
     */
    @Override
    public synchronized void encryptSegment(
        ByteBuffer plaintext, boolean isLastSegment, ByteBuffer ciphertext)
        throws GeneralSecurityException {
      cipher.init(
          Cipher.ENCRYPT_MODE,
          keySpec,
          paramsForSegment(noncePrefix, encryptedSegments, isLastSegment));
      encryptedSegments++;
      cipher.doFinal(plaintext, ciphertext);
    }

    /**
     * Encrypt a segment consisting of two parts. This method simplifies the case where one part of
     * the plaintext is buffered and the other part is passed in by the caller.
     */
    @Override
    public synchronized void encryptSegment(
        ByteBuffer part1, ByteBuffer part2, boolean isLastSegment, ByteBuffer ciphertext)
        throws GeneralSecurityException {
      cipher.init(
          Cipher.ENCRYPT_MODE,
          keySpec,
          paramsForSegment(noncePrefix, encryptedSegments, isLastSegment));
      encryptedSegments++;
      cipher.update(part1, ciphertext);
      cipher.doFinal(part2, ciphertext);
    }

    @Override
    public synchronized int getEncryptedSegments() {
      return encryptedSegments;
    }
  }

  /** An instance of a crypter used to decrypt a ciphertext stream. */
  class AesGcmHkdfStreamDecrypter implements StreamSegmentDecrypter {
    private SecretKeySpec keySpec;
    private Cipher cipher;
    private byte[] noncePrefix;

    AesGcmHkdfStreamDecrypter() {};

    @Override
    public synchronized void init(ByteBuffer header, byte[] aad) throws GeneralSecurityException {
      if (header.remaining() != getHeaderLength()) {
        throw new InvalidAlgorithmParameterException("Invalid header length");
      }
      byte firstByte = header.get();
      if (firstByte != getHeaderLength()) {
        // We expect the first byte to be the length of the header.
        // If this is not the case then either the ciphertext is incorrectly
        // aligned or invalid.
        throw new GeneralSecurityException("Invalid ciphertext");
      }
      noncePrefix = new byte[NONCE_PREFIX_IN_BYTES];
      byte[] salt = new byte[keySizeInBytes];
      header.get(salt);
      header.get(noncePrefix);
      keySpec = deriveKeySpec(salt, aad);
      cipher = cipherInstance();
    }

    @Override
    public synchronized void decryptSegment(
        ByteBuffer ciphertext, int segmentNr, boolean isLastSegment, ByteBuffer plaintext)
        throws GeneralSecurityException {
      GCMParameterSpec params = paramsForSegment(noncePrefix, segmentNr, isLastSegment);
      cipher.init(Cipher.DECRYPT_MODE, keySpec, params);
      cipher.doFinal(ciphertext, plaintext);
    }
  }
}
