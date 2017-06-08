
package com.google.crypto.tink.subtle;

import com.google.crypto.tink.StreamingEncryption;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Streaming encryption using AES-GCM.
 *
 * Each ciphertext uses a new AES-GCM key that is derived from the key derivation key,
 * a randomly chosen salt of the same size as the key and a nonce prefix.
 *
 * The the format of a ciphertext is
 *   header || segment_0 || segment_1 || ... || segment_k.
 * The header has size this.headerLength(). Its format is
 *   headerLength || salt || prefix.
 * where headerLength is 1 byte determining the size of the header, salt is a salt used in the
 * key derivation and prefix is the prefix of the nonce.
 * In principle headerLength is redundant information, since the length of the header can be
 * determined from the key size.
 *
 * segment_i is the i-th segment of the ciphertext. The size of segment_1 .. segment_{k-1}
 * is ciphertextSegmentSize. segment_0 is shorter, so that segment_0, the header
 * and other information of size firstSegmentOffset align with ciphertextSegmentSize.
 */
public class AesGcmStreaming implements StreamingEncryption {
  // TODO(bleichen): Some things that are not yet decided:
  //   - What can we assume about the state of objects after getting an exception?
  //   - Should there be a simple test to detect invalid ciphertext offsets?
  //   - Should we encode the size of the header?
  //   - Should we encode the size of the segments?
  //   - Should a version be included in the header to allow header modification?
  //   - Should we allow other information, header and the first segment the to be a multiple of
  //     ciphertextSegmentSize?
  //   - This implementation fixes a number of parameters. Should there be more options?
  // TODO(bleichen): Stuff that should be done in the future:
  //   - Some classes do not heavily depend on the underlying cipher, could be factored out and
  //     reused with other ciphers: AesGcmEncryptingChannel, AesGcmInputStream and
  //     AesGcmSeekableByteChannel.
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

  private int keySizeInBits;
  private int ciphertextSegmentSize;
  private int plaintextSegmentSize;
  private int firstSegmentOffset;
  private byte[] ikm;

  /**
   * Initializes a streaming primitive with a key derivation key and encryption parameters.
   * @params ikm input keying material used to derive sub keys.
   * @keySizeInBits the key size of the sub keys
   * @ciphertextSegmentSize the size of ciphertext segments.
   * @firstSegmentOffset the offset of the first ciphertext segment. That means the first
   *    segment has size ciphertextSegmentSize - headerLength() - firstSegmentOffset
   * @throws InvalidAlgorithmParameterException if ikm is too short, the key size not supported or
   *    ciphertextSegmentSize is to short.
   */
  public AesGcmStreaming(
      byte[] ikm,
      int keySizeInBits,
      int ciphertextSegmentSize,
      int firstSegmentOffset) throws InvalidAlgorithmParameterException {
    // Checks
    if (ikm.length < 16) {
      throw new InvalidAlgorithmParameterException("ikm to short");
    }
    boolean isValidKeySize = keySizeInBits == 128 || keySizeInBits == 192 || keySizeInBits == 256;
    if (!isValidKeySize) {
      throw new InvalidAlgorithmParameterException("Invalid key size");
    }
    if (ciphertextSegmentSize <= firstSegmentOffset + headerLength() + TAG_SIZE_IN_BYTES) {
      throw new InvalidAlgorithmParameterException("ciphertextSegmentSize too small");
    }
    this.ikm = Arrays.copyOf(ikm, ikm.length);
    this.keySizeInBits = keySizeInBits;
    this.ciphertextSegmentSize = ciphertextSegmentSize;
    this.firstSegmentOffset = firstSegmentOffset;
    this.plaintextSegmentSize = ciphertextSegmentSize - TAG_SIZE_IN_BYTES;
  }

  public int getFirstSegmentOffset() {
    return firstSegmentOffset;
  }

  private int headerLength() {
    return 1 + keySizeInBits / 8 + NONCE_PREFIX_IN_BYTES;
  }

  private int ciphertextOffset() {
    return headerLength() + firstSegmentOffset;
  }

  /**
   * Returns the number of bytes that a ciphertext segment
   * is longer than the corresponding plaintext segment.
   * Typically this is the size of the tag.
   */
  private int ciphertextOverhead() {
    return TAG_SIZE_IN_BYTES;
  }

  /**
   * Returns the expected size of the ciphertext for a given plaintext
   * The returned value includes the header and offset.
   */
  public long expectedCiphertextSize(long plaintextSize) {
    long offset = ciphertextOffset();
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
    return Random.randBytes(keySizeInBits / 8);
  }

  public int getSegmentNr(long plaintextPosition) {
    return (int) ((plaintextPosition + ciphertextOffset()) / plaintextSegmentSize);
  }

  public int getCiphertextSegmentSize() {
    return ciphertextSegmentSize;
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

  private SecretKeySpec deriveKeySpec(
      byte[] salt,
      byte[] aad) throws GeneralSecurityException {
    byte[] key = Hkdf.computeHkdf(MAC_ALGORITHM, ikm, salt, aad, keySizeInBits / 8);
    return new SecretKeySpec(key, "AES");
  }

  /**
   * An instance of a crypter used to encrypt a plaintext stream.
   * The instances have state: encryptedSegments counts the number of encrypted
   * segments. This state is used to generate the IV for each segment.
   * By enforcing that only the method encryptSegment can increment this state,
   * we can guarantee that the IV does not repeat.
   */
  class AesGcmStreamEncrypter {
    private final SecretKeySpec keySpec;
    private final Cipher cipher;
    private final byte[] noncePrefix;
    private ByteBuffer header;
    private int encryptedSegments = 0;

    public AesGcmStreamEncrypter(byte[] aad) 
        throws GeneralSecurityException {
      cipher = cipherInstance();
      encryptedSegments = 0;
      byte[] salt = randomSalt();
      noncePrefix = randomNonce();
      header = ByteBuffer.allocate(headerLength());
      header.put((byte) headerLength());
      header.put(salt);
      header.put(noncePrefix);
      header.flip();
      keySpec = deriveKeySpec(salt, aad);
    }

    public ByteBuffer getHeader() {
      return header.asReadOnlyBuffer();
    }

    /**
     * Encrypts the next plaintext segment.
     * This uses encryptedSegments as the segment number for the encryption.
     */
    public synchronized void encryptSegment(
        ByteBuffer plaintext, boolean isLastSegment, ByteBuffer ciphertext)
        throws GeneralSecurityException {
      cipher.init(Cipher.ENCRYPT_MODE, keySpec,
                  paramsForSegment(noncePrefix, encryptedSegments, isLastSegment));
      encryptedSegments++;
      cipher.doFinal(plaintext, ciphertext);
    }

    /**
     * Encrypt a segment consisting of two parts.
     * This method simplifies the case where one part of the plaintext is buffered and the other part
     * is passed in by the caller.
     */
    public synchronized void encryptSegment(
        ByteBuffer part1, ByteBuffer part2, boolean isLastSegment, ByteBuffer ciphertext)
        throws GeneralSecurityException {
      cipher.init(Cipher.ENCRYPT_MODE, keySpec,
                  paramsForSegment(noncePrefix, encryptedSegments, isLastSegment));
      encryptedSegments++;
      cipher.update(part1, ciphertext);
      cipher.doFinal(part2, ciphertext);
    }

    public int getEncryptedSegments() {
      return encryptedSegments;
    }
  }

  class AesGcmStreamDecrypter {
    private final SecretKeySpec keySpec;
    private final Cipher cipher;
    private final byte[] noncePrefix;

    public AesGcmStreamDecrypter(ByteBuffer header, byte[] aad) throws GeneralSecurityException {
      if (header.remaining() != headerLength()) {
        throw new InvalidAlgorithmParameterException("Invalid header length");
      }
      byte firstByte = header.get();
      if (firstByte != headerLength()) {
        // We expect the first byte to be the length of the header.
        // If this is not the case then either the ciphertext is incorrectly
        // aligned or invalid.
        throw new GeneralSecurityException("Invalid ciphertext");
      }
      noncePrefix = new byte[NONCE_PREFIX_IN_BYTES];
      byte[] salt = new byte[keySizeInBits / 8];
      header.get(salt);
      header.get(noncePrefix);
      keySpec = deriveKeySpec(salt, aad);
      cipher = cipherInstance();
    }

    public synchronized void decryptSegment(
        ByteBuffer ciphertext, int segmentNr, boolean isLastSegment, ByteBuffer plaintext)
        throws GeneralSecurityException {
      GCMParameterSpec params = paramsForSegment(noncePrefix, segmentNr, isLastSegment);
      cipher.init(Cipher.DECRYPT_MODE, keySpec, params);
      cipher.doFinal(ciphertext, plaintext);
    }
  }

  class AesGcmEncryptingChannel implements WritableByteChannel {
    private WritableByteChannel ciphertextChannel;
    private AesGcmStreamEncrypter encrypter;
    ByteBuffer ptBuffer;  // contains plaintext that has not yet been encrypted.
    ByteBuffer ctBuffer;  // contains ciphertext that has not been written to ciphertextChannel.
    boolean open = true;

    public AesGcmEncryptingChannel(
        AesGcmStreamEncrypter encrypter,
        WritableByteChannel ciphertextChannel) throws GeneralSecurityException, IOException {
      this.ciphertextChannel = ciphertextChannel;
      this.encrypter = encrypter;
      ptBuffer = ByteBuffer.allocate(plaintextSegmentSize);
      ptBuffer.limit(plaintextSegmentSize - ciphertextOffset());
      ctBuffer = ByteBuffer.allocate(ciphertextSegmentSize);
      // At this point, ciphertextChannel might not yet be ready to receive bytes.
      // Buffering the header in ctBuffer ensures that the header will be written when writing to
      // ciphertextChannel is possible.
      ctBuffer.put(encrypter.getHeader());
      ctBuffer.flip();
      ciphertextChannel.write(ctBuffer);
    }

    @Override
    public synchronized int write(ByteBuffer pt) throws IOException {
      if (ctBuffer.remaining() > 0) {
        ciphertextChannel.write(ctBuffer);
      }
      int startPosition = pt.position();
      while (pt.remaining() > ptBuffer.remaining()) {
        if (ctBuffer.remaining() > 0) {
          return pt.position() - startPosition;
        }
        int sliceSize = ptBuffer.remaining();
        ByteBuffer slice = pt.slice();
        slice.limit(sliceSize);
        pt.position(pt.position() + sliceSize);
        try {
          ptBuffer.flip();
          ctBuffer.clear();
          encrypter.encryptSegment(ptBuffer, slice, false, ctBuffer);
        } catch (GeneralSecurityException ex) {
          throw new IOException(ex);
        }
        ctBuffer.flip();
        ciphertextChannel.write(ctBuffer);
        ptBuffer.clear();
        ptBuffer.limit(plaintextSegmentSize);
      }
      ptBuffer.put(pt);
      return pt.position() - startPosition;
    }

    @Override
    public synchronized void close() throws IOException {
      // TODO(bleichen): Is there a way to fully write the remaining ciphertext?
      //   The following is the strategy from java.nio.channels.Channels.writeFullyImpl
      //   I.e. try writing as long as at least one byte is written.
      while (ctBuffer.remaining() > 0) {
        int n = ciphertextChannel.write(ctBuffer);
        if (n <= 0) {
          throw new IOException("Failed to write ciphertext before closing");
        }
      }
      try {
        ctBuffer.clear();
        ptBuffer.flip();
        encrypter.encryptSegment(ptBuffer, true, ctBuffer);
      } catch (GeneralSecurityException ex) {
        // TODO(bleichen): define the state of this. E.g. open = false;
        throw new IOException(ex);
      }
      ctBuffer.flip();
      while (ctBuffer.remaining() > 0) {
        int n = ciphertextChannel.write(ctBuffer);
        if (n <= 0) {
          throw new IOException("Failed to write ciphertext before closing");
        }
      }
      ciphertextChannel.close();
      open = false;
    }

    @Override
    public boolean isOpen() {
      return open;
    }
  }

  /**
   * Returns a WritableByteChannel for plaintext.
   * @param ciphertextChannel the channel to which the ciphertext is written.
   * @param associatedData data associated with the plaintext. This data is authenticated
   *        but not encrypted. It must be passed into the decryption.
   */
  @Override
  public WritableByteChannel newEncryptingChannel(
      WritableByteChannel ciphertextChannel, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    AesGcmStreamEncrypter encrypter = new AesGcmStreamEncrypter(associatedData);
    return new AesGcmEncryptingChannel(encrypter, ciphertextChannel);
  }

  /**
   * An instance of a ReadableByteChannel that returns the plaintext for some ciphertext.
   */
  class AesGcmReadableByteChannel implements ReadableByteChannel {
    /* The stream containing the ciphertext */
    private ReadableByteChannel ciphertextChannel;

    /**
     * A buffer containing ciphertext that has not yet been decrypted.
     * The limit of ciphertextSegment is set such that it can contain segment plus the first
     * character of the next segment. It is necessary to read a segment plus one more byte
     * to decrypt a segment, since the last segment of a ciphertext is encrypted differently.
     */
    private ByteBuffer ciphertextSegment;

    /**
     * A buffer containing a plaintext segment.
     * The bytes in the range plaintexSegment.position() .. plaintextSegment.limit() - 1
     * are plaintext that have been decrypted but not yet read out of AesGcmInputStream.
     */
    private ByteBuffer plaintextSegment;

    /* A buffer containg the header information from the ciphertext. */
    private ByteBuffer header;

    /* Determines whether the header has been completely read. */
    private boolean headerRead;

    /* Indicates whether the end of this InputStream has been reached. */
    private boolean endOfCiphertext;

    /* Indicates whether the end of the plaintext has been reached. */
    private boolean endOfPlaintext;

    /**
     * Indicates whether this stream is in a defined state.
     * Currently the state of this instance becomes undefined when
     * an authentication error has occured.
     */
    private boolean definedState;

    /**
     * The position in the plaintext. This is the same as the number of bytes
     * alread read this.
     */
    private long plaintextPosition;

    /**
     * The additional data that is authenticated with the ciphertext.
     */
    private byte[] aad;

    /**
     * The number of the current segment of ciphertext buffered in ciphertexSegment.
     */
    private int segmentNr;

    private AesGcmStreamDecrypter decrypter;

    public AesGcmReadableByteChannel(
        ReadableByteChannel ciphertextChannel, byte[] associatedData)
        throws GeneralSecurityException, IOException {
      this.ciphertextChannel = ciphertextChannel;
      header = ByteBuffer.allocate(headerLength());
      aad = Arrays.copyOf(associatedData, associatedData.length);

      // ciphertextSegment is one byte longer than a ciphertext segment,
      // so that the code can decide if the current segment is the last segment in the
      // stream.
      ciphertextSegment = ByteBuffer.allocate(ciphertextSegmentSize + 1);
      ciphertextSegment.limit(0);
      plaintextSegment = ByteBuffer.allocate(plaintextSegmentSize);
      plaintextSegment.limit(0);
      plaintextPosition = 0;
      headerRead = false;
      endOfCiphertext = false;
      endOfPlaintext = false;
      segmentNr = 0;
      definedState = true;
      decrypter = null;
    }

    /**
     * Reads some ciphertext.
     * @param buffer the destination for the ciphertext.
     * @throws IOException when an exception reading the ciphertext stream occurs.
     */
    private void readSomeCiphertext(ByteBuffer buffer) throws IOException {
      int read;
      do {
        read = ciphertextChannel.read(buffer);
      } while (read > 0 && buffer.remaining() > 0);
      if (read == -1) {
        endOfCiphertext = true;
      }
    }

    /**
     * Tries to read the header of the ciphertext.
     * @returns true if the header has been fully read and false if not enogh bytes were available
     *          from the ciphertext stream.
     * @throws IOException when an exception occurs while reading the ciphertextStream or when
     *         the header is too short.
     */
    private boolean tryReadHeader() throws IOException {
      if (endOfCiphertext) {
        throw new IOException("Ciphertext is too short");
      }
      readSomeCiphertext(header);
      if (header.remaining() > 0) {
        return false;
      } else {
        header.flip();
        try {
          decrypter = new AesGcmStreamDecrypter(header, aad);
          headerRead = true;
        } catch (GeneralSecurityException ex) {
          // TODO(bleichen): Try to define the state of this.
          setUndefinedState();
          throw new IOException(ex);
        }
        return true;
      }
    }

    private void setUndefinedState() {
      definedState = false;
      plaintextSegment.limit(0);
    }

    /**
     * Tries to load the next plaintext segment.
     */
    private boolean tryLoadSegment() throws IOException {
      // Try filling the ciphertextSegment
      if (!endOfCiphertext) {
        readSomeCiphertext(ciphertextSegment);
      }
      if (ciphertextSegment.remaining() > 0 && !endOfCiphertext) {
        // we have not enough ciphertext for the next segment
        return false;
      }
      byte lastByte = 0;
      if (!endOfCiphertext) {
        lastByte = ciphertextSegment.get(ciphertextSegment.position() - 1);
        ciphertextSegment.position(ciphertextSegment.position() - 1);
      }
      ciphertextSegment.flip();
      plaintextSegment.clear();
      try {
        decrypter.decryptSegment(
            ciphertextSegment, segmentNr, endOfCiphertext, plaintextSegment);
      } catch (GeneralSecurityException ex) {
        // The current segment did not validate.
        // Currently this means that decryption cannot resume.
        setUndefinedState();
        throw new IOException(ex);
      }
      segmentNr += 1;
      plaintextSegment.flip();
      ciphertextSegment.clear();
      if (!endOfCiphertext) {
        ciphertextSegment.clear();
        ciphertextSegment.limit(ciphertextSegmentSize + 1);
        ciphertextSegment.put(lastByte);
      }
      return true;
    }

    @Override
    public synchronized int read(ByteBuffer dst) throws IOException {
      if (!definedState) {
        throw new IOException("This AesGcmReadableByteChannel is in an undefined state");
      }
      if (!headerRead) {
        if (!tryReadHeader()) {
          return 0;
        }
        int firstSegmentLength = ciphertextSegmentSize - ciphertextOffset();
        ciphertextSegment.clear();
        ciphertextSegment.limit(firstSegmentLength + 1);
        plaintextPosition = 0;
      }
      if (endOfPlaintext) {
        return -1;
      }
      int startPosition = dst.position();
      while (dst.remaining() > 0) {
        if (plaintextSegment.remaining() == 0) {
          if (endOfCiphertext) {
            endOfPlaintext = true;
            break;
          }
          if (!tryLoadSegment()) {
            break;
          }
        }
        if (plaintextSegment.remaining() <= dst.remaining()) {
          int sliceSize = plaintextSegment.remaining();
          dst.put(plaintextSegment);
          plaintextPosition += sliceSize;
        } else {
          int sliceSize = dst.remaining();
          ByteBuffer slice = plaintextSegment.duplicate();
          slice.limit(slice.position() + sliceSize);
          dst.put(slice);
          plaintextSegment.position(plaintextSegment.position() + sliceSize);
          plaintextPosition += sliceSize;
        }
      }
      return dst.position() - startPosition;
    }

    @Override
    public void close() throws IOException {
      ciphertextChannel.close();
    }

    @Override
    public boolean isOpen() {
      return ciphertextChannel.isOpen();
    }


    /* Returns the state of the channel. */
    @Override
    public String toString() {
      StringBuilder res =
        new StringBuilder();
      res.append("AesGcmReadableByteChannel")
         .append("\nplaintextPosition:").append(plaintextPosition)
         .append("\nsegmentNr:").append(segmentNr)
         .append("\nciphertextSegmentSize:").append(ciphertextSegmentSize)
         .append("\nheaderRead:").append(headerRead)
         .append("\nendOfCiphertext:").append(endOfCiphertext)
         .append("\nendOfPlaintext:").append(endOfPlaintext)
         .append("\ndefinedState:").append(definedState)
         .append("\nHeader")
         .append(" position:").append(header.position())
         .append(" limit:").append(header.position())
         .append("\nciphertextSgement")
         .append(" postion:").append(ciphertextSegment.position())
         .append(" limit:").append(ciphertextSegment.limit())
         .append("\nplaintextSegment")
         .append(" position:").append(plaintextSegment.position())
         .append(" limit:").append(plaintextSegment.limit());
      return res.toString();
    }
  }

  @Override
  public ReadableByteChannel newDecryptingChannel(
      ReadableByteChannel ciphertextChannel,
      byte[] associatedData)
      throws GeneralSecurityException, IOException {
    return new AesGcmReadableByteChannel(ciphertextChannel, associatedData);
  }

  class AesGcmSeekableByteChannel implements SeekableByteChannel {
    private final SeekableByteChannel ciphertextChannel;
    private final ByteBuffer ciphertextSegment;
    private final ByteBuffer plaintextSegment;
    private final ByteBuffer header;
    private final long ciphertextChannelSize;  // unverified size of the ciphertext
    private final int numberOfSegments;  // unverified number of segments
    private final int lastCiphertextSegmentSize;  // unverified size of the last segment.
    private final byte[] aad;
    private AesGcmStreamDecrypter decrypter;
    private long plaintextPosition;
    private long plaintextSize;
    private boolean headerRead;
    private boolean isCurrentSegmentDecrypted;
    private int currentSegmentNr;
    private boolean isopen;

    public AesGcmSeekableByteChannel(SeekableByteChannel ciphertext,
                                     byte[] associatedData)
                                     throws IOException, GeneralSecurityException {
      this.ciphertextChannel = ciphertext;
      this.header = ByteBuffer.allocate(headerLength());
      this.ciphertextSegment = ByteBuffer.allocate(ciphertextSegmentSize);
      this.plaintextSegment = ByteBuffer.allocate(plaintextSegmentSize);
      this.plaintextPosition = 0;
      this.headerRead = false;
      this.currentSegmentNr = -1;
      this.isCurrentSegmentDecrypted = false;
      this.ciphertextChannelSize = ciphertextChannel.size();
      this.aad = Arrays.copyOf(associatedData, associatedData.length);
      this.isopen = ciphertextChannel.isOpen();
      int  fullSegments = (int) (ciphertextChannelSize / ciphertextSegmentSize);
      int remainder = (int) (ciphertextChannelSize % ciphertextSegmentSize);
      int plaintextSegmentSize = ciphertextSegmentSize - ciphertextOverhead();
      if (remainder > 0) {
        numberOfSegments = fullSegments + 1;
        if (remainder < ciphertextOverhead()) {
          throw new IOException("Invalid ciphertext size");
        }
        lastCiphertextSegmentSize = remainder;
      } else {
        numberOfSegments = fullSegments;
        lastCiphertextSegmentSize = ciphertextSegmentSize;
      }
      long overhead = (long) numberOfSegments * ciphertextOverhead() + ciphertextOffset();
      if (overhead > ciphertextChannelSize) {
        throw new IOException("Ciphertext is too short");
      }
      plaintextSize = ciphertextChannelSize - overhead;
    }

    /**
     * A description of the state of this AesGcmSeekableByteChannel.
     * While this description does not contain plaintext or key material
     * it contains length information that might be confidential.
     */
    @Override
    public String toString() {
      StringBuilder res =
        new StringBuilder();
      String ctChannel;
      try {
        ctChannel = "position:" + ciphertextChannel.position();
      } catch (IOException ex) {
        ctChannel = "position: n/a";
      }
      res.append("AesGcmSeekableByteChannel")
         .append("\nciphertextChannel").append(ctChannel)
         .append("\nciphertextChannelSize:").append(ciphertextChannelSize)
         .append("\nplaintextSize:").append(plaintextSize)
         .append("\nciphertextSegmentSize:").append(ciphertextSegmentSize)
         .append("\nnumberOfSegments:").append(numberOfSegments)
         .append("\nheaderRead:").append(headerRead)
         .append("\nplaintextPosition:").append(plaintextPosition)
         .append("\nHeader")
         .append(" position:").append(header.position())
         .append(" limit:").append(header.position())
         .append("\ncurrentSegmentNr:").append(currentSegmentNr)
         .append("\nciphertextSgement")
         .append(" postion:").append(ciphertextSegment.position())
         .append(" limit:").append(ciphertextSegment.limit())
         .append("\nisCurrentSegmentDecrypted:").append(isCurrentSegmentDecrypted)
         .append("\nplaintextSegment")
         .append(" position:").append(plaintextSegment.position())
         .append(" limit:").append(plaintextSegment.limit());
      return res.toString();
    }

    /**
     * Returns the position of of this channel.
     * The position is relative to the plaintext.
     */
    @Override
    public long position() {
      return plaintextPosition;
    }

    /**
     * Sets the position in the plaintext.
     * Setting the position to a value greater than the plaintext size is legal.
     * A later attempt to read byte will throw an IOException.
     */
    @Override
    public SeekableByteChannel position(long newPosition) {
      plaintextPosition = newPosition;
      return this;
    }

    /**
     * Tries to read the header of the ciphertext and derive the key used for the
     * ciphertext from the information in the header.
     *
     * @returns true if the header was fully read and has a correct format.
     *               Returns false if the header could not be read.
     * @throws IOException if the header was incorrectly formatted or if there
     *         was an exception during the key derivation.
     */
    private boolean tryReadHeader() throws IOException {
      ciphertextChannel.position(header.position() + firstSegmentOffset);
      ciphertextChannel.read(header);
      if (header.remaining() > 0) {
        return false;
      } else {
        header.flip();
        try {
          decrypter = new AesGcmStreamDecrypter(header, aad);
          headerRead = true;
        } catch (GeneralSecurityException ex) {
          // TODO(bleichen): Define the state of this.
          throw new IOException(ex);
        }
        return true;
      }
    }

    /**
     * Tries to read and decrypt a ciphertext segment.
     * @param segmentNr the number of the segment
     * @returns true if the segment was read and correctly decrypted.
     *          Returns false if the segment could not be fully read.
     * @throws IOException if there was an exception reading the ciphertext,
     *         if the segment number was incorrect, or
     *         if there was an exception trying to decrypt the ciphertext segment.
     */
    private boolean tryLoadSegment(int segmentNr) throws IOException {
      if (segmentNr < 0 || segmentNr >= numberOfSegments) {
        throw new IOException("Invalid position");
      }
      boolean isLast = segmentNr == numberOfSegments - 1;
      if (segmentNr == currentSegmentNr) {
        if (isCurrentSegmentDecrypted) {
          return true;
        }
      } else {
        // segmentNr != currentSegmentNr
        long ciphertextPosition = (long) segmentNr * ciphertextSegmentSize;
        int segmentSize = ciphertextSegmentSize;
        if (isLast) {
          segmentSize = lastCiphertextSegmentSize;
        }
        if (segmentNr == 0) {
          segmentSize -= ciphertextOffset();
          ciphertextPosition = ciphertextOffset();
        }
        ciphertextChannel.position(ciphertextPosition);
        ciphertextSegment.clear();
        ciphertextSegment.limit(segmentSize);
        currentSegmentNr = segmentNr;
        isCurrentSegmentDecrypted = false;
      }
      if (ciphertextSegment.remaining() > 0) {
        ciphertextChannel.read(ciphertextSegment);
      }
      if (ciphertextSegment.remaining() > 0) {
        return false;
      }
      ciphertextSegment.flip();
      plaintextSegment.clear();
      try {
        decrypter.decryptSegment(ciphertextSegment, segmentNr, isLast, plaintextSegment);
      } catch (GeneralSecurityException ex) {
        // The current segment did not validate. Ensure that this instance remains
        // in a valid state.
        currentSegmentNr = -1;
        throw new IOException("Failed to decrypt", ex);
      }
      plaintextSegment.flip();
      isCurrentSegmentDecrypted = true;
      return true;
    }

    /**
     * Returns true if plaintextPositon is at the end of the file
     * and this has been verified, by decrypting the last segment.
     */
    private boolean reachedEnd() {
      return (isCurrentSegmentDecrypted &&
              currentSegmentNr == numberOfSegments - 1 &&
              plaintextSegment.remaining() == 0);
    }

    @Override
    public synchronized int read(ByteBuffer dst) throws IOException {
      if (!isopen) {
        throw new ClosedChannelException();
      }
      if (!headerRead) {
        if (!tryReadHeader()) {
          return 0;
        }
      }
      int startPos = dst.position();
      while (dst.remaining() > 0 && plaintextPosition < plaintextSize) {
        // Determine segmentNr for the plaintext to read and the offset in
        // the plaintext, where reading should start.
        int segmentNr = getSegmentNr(plaintextPosition);
        int segmentOffset;
        if (segmentNr == 0) {
           segmentOffset = (int) plaintextPosition;
        } else {
           segmentOffset = (int) ((plaintextPosition +  ciphertextOffset()) % plaintextSegmentSize);
        }

        if (tryLoadSegment(segmentNr)) {
          plaintextSegment.position(segmentOffset);
          if (plaintextSegment.remaining() <= dst.remaining()) {
            plaintextPosition += plaintextSegment.remaining();
            dst.put(plaintextSegment);
          } else {
            int sliceSize = dst.remaining();
            ByteBuffer slice = plaintextSegment.duplicate();
            slice.limit(slice.position() + sliceSize);
            dst.put(slice);
            plaintextPosition += sliceSize;
            plaintextSegment.position(plaintextSegment.position() + sliceSize);
          }
        } else {
          break;
        }
      }
      int read = dst.position() - startPos;
      if (read == 0 && reachedEnd()) {
        return -1;
      }
      return read;
    }

    /**
     * Returns the expected size of the plaintext.
     * Note that this implementation does not perform an integrity check on the size.
     * I.e. if the file has been truncated then size() will return the wrong
     * result. Reading the last block of the ciphertext will verify whether size()
     * is correct.
     */
    @Override
    public long size() {
      return plaintextSize;
    }

    public long verifiedSize() throws IOException {
      if (tryLoadSegment(numberOfSegments - 1)) {
        return plaintextSize;
      } else {
        throw new IOException("could not verify the size");
      }
    }

    @Override
    public SeekableByteChannel truncate(long size) throws NonWritableChannelException {
      throw new NonWritableChannelException();
    }

    @Override
    public int write(ByteBuffer src) throws NonWritableChannelException {
      throw new NonWritableChannelException();
    }

    @Override
    public void close() throws IOException {
      ciphertextChannel.close();
      isopen = false;
    }

    @Override
    public boolean isOpen() {
      return isopen;
    }
  }

  @Override
  public SeekableByteChannel newSeekableDecryptingChannel(
      SeekableByteChannel ciphertextSource,
      byte[] associatedData)
      throws GeneralSecurityException, IOException {
    return new AesGcmSeekableByteChannel(ciphertextSource, associatedData);
  }
}

