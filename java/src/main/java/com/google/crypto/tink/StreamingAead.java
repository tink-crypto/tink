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

package com.google.crypto.tink;

import com.google.crypto.tink.annotations.Alpha;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;

/**
 * An interface for streaming authenticated encryption with additional data.
 *
 * <p>Streaming encryption is typically used for encrypting large plaintexts such as large files.
 * Tink may eventually contain multiple interfaces for streaming encryption depending on the
 * supported properties. This interface supports a streaming interface for symmetric encryption with
 * authentication. The underlying encryption modes are selected so that partial plaintext can be
 * obtained fast by decrypting and authenticating just part of the ciphertext.
 *
 * <pre>
 * Security:
 * =========
 * Instances of StreamingAead must follow the OAE2 definition as proposed in the paper
 * "Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance" by Hoang, Reyhanitabar,
 * Rogaway and Vizár https://eprint.iacr.org/2015/189.pdf
 *
 * Restrictions:
 * =============
 * Encryption must be done in one session. There is no possibility to modify an existing
 * ciphertext or append to it (other than reencrypt the whold file again). One reason
 * for this restriction is the use of AES-GCM as one cipher to implement this interface.
 * If single segments are modified then this is equivalent to reusing the same IV twice, but
 * reusing an IV twice leaks an AES-GCM key. Another reason is that implementations of this
 * interface have no protection against roll-back attacks: an attacker can always try to restore
 * a previous version of the file without detection.
 *
 * Blocking vs non-blocking I/O
 * ============================
 * Channels can be in blocking (i.e. always waits untile the requrested number of bytes have been
 * processed) or non-blocking mode.
 * If the channel provided to the streaming encryption is in blocking mode then encryption and
 * decryption have the same property. That is encryption always processes all the plaintext passed
 * in and waits until complete segments have been written to the ciphertext channel. Similarly,
 * decryption blocks until sufficiently many bytes have been read from the ciphertext channel until
 * all the requested plaintext has been decrypted and authenticated, an IOException occurred, or the
 * end of the plaintext has been reached.
 *
 * If the channel provided to the streaming encryption is in non-blocking mode, then encryption and
 * decryption are also non-blocking. Since encryption and decryption is done in segments it is
 * possible that for example a call attempting to read() returns no plaintext at all even if
 * partial ciphertext was read from the underlying channel.
 *
 * Sample encryption:
 * ==================
 * <pre>{@code
 * StreamingAead s = ...
 * java.nio.channels.FileChannel ciphertextDestination =
 *     new FileOutputStream(ciphertextFile).getChannel();
 * byte[] aad = ...
 * WritableByteChannel encryptingChannel = s.newEncryptingChannel(ciphertextDestination, aad);
 * while ( ... ) {
 *   int r = encryptingChannel.write(buffer);
 *   ...
 * }
 * encryptingChannel.close();
 * }</pre>
 *
 * Sample full decryption:
 * =======================
 * <pre>{@code
 * StreamingAead s = ...
 * java.nio.channels.FileChannel ciphertextDestination =
 *     new FileInputStream(ciphertextFile).getChannel();
 * byte[] aad = ...
 * SeekableByteChannel decryptingChannel = s.newDecryptingChannel(ciphertextDestination, aad);
 * int chunkSize = ...
 * ByteBuffer buffer = ByteBuffer.allocate(chunkSize);
 * do {
 *   buffer.clear();
 *   int cnt = decryptingChannel.read(buffer);
 *   if (cnt > 0) {
 *     // Process cnt bytes of plaintext
 *   } else if (read == -1) {
 *     // End of plaintext detected
 *     break;
 *   } else if (read == 0) {
 *     // No ciphertext is available at the moment.
 *   }
 * }
 * }</pre>
 */
@Alpha
public interface StreamingAead {

  /**
   * Returns a WritableByteChannel for plaintext.
   *
   * @param ciphertextDestination the channel to which the ciphertext is written.
   * @param associatedData data associated with the plaintext. This data is authenticated but not
   *     encrypted. It must be passed into the decryption.
   */
  WritableByteChannel newEncryptingChannel(
      WritableByteChannel ciphertextDestination, byte[] associatedData)
      throws GeneralSecurityException, IOException;

  /**
   * Returns a SeekableByteChannel that allows to access the plaintext.
   *
   * @param ciphertextSource the ciphertext
   * @param associatedData the data associated with the ciphertext.
   * @return a SeekableByteChannel that allows random read access to the plaintext. The following
   *     methods of SeekableByteChannel are implemented:
   *     <ul>
   *       <li><code>long position()</code> Returns the channel's position in the plaintext.
   *       <li><code>SeekableByteChannel  position(long newPosition)</code> Sets the channel's
   *           position. Setting the position to a value greater than the plaintext size is legal. A
   *           later attempt to read byte will immediately return an end-of-file indication.
   *       <li><code>int read(ByteBuffer dst)</code> Bytes are read starting at the channel's
   *           position, and then the position is updated with the number of bytes actually read.
   *           All bytes returned have been authenticated. If the end of the stream has been reached
   *           -1 is returned. A result of -1 is authenticated (e.g. by checking the MAC of the last
   *           ciphertext chunk.) Throws java.io.IOException if a MAC verification failed. read
   *           attempt to fill dst, but may return less bytes than requested if reads to
   *           ciphertextSource do not return the requested number of bytes or if the plaintext
   *           ended. TODO(bleichen): Should we extend the interface with read(ByteBuffer dst, long
   *           position) to avoid race conditions?
   *       <li><code>long size()</code> Returns the size of the plaintext. (TODO: Decide whether the
   *           result should be authenticated)
   *       <li><code>SeekableByteChannel truncate(long size)</code> throws
   *           NonWritableChannelException because the channel is read-only.
   *       <li><code>int write(ByteBuffer src)</code> throws NonWritableChannelException because the
   *           channel is read-only.
   *       <li><code>close()</code> closes the channel
   *       <li><code>isOpen()</code>
   *     </ul>
   *
   * @throws GeneralSecurityException if the header of the ciphertext is corrupt or if the
   *     associatedData is not correct.
   * @throws IOException if an IOException occurred while reading from ciphertextDestination.
   */
  SeekableByteChannel newSeekableDecryptingChannel(
      SeekableByteChannel ciphertextSource, byte[] associatedData)
      throws GeneralSecurityException, IOException;

  ReadableByteChannel newDecryptingChannel(
      ReadableByteChannel ciphertextChannel, byte[] associatedData)
      throws GeneralSecurityException, IOException;

  /**
   * Returns a wrapper around {@code ciphertextSource}, such that any write-operation via the
   * wrapper results in AEAD-encryption of the written data, using {@code additionalData} as
   * additional authenticated data. The additional data is not included in the ciphertext and has to
   * be passed in as parameter for decryption.
   */
  InputStream newDecryptingStream(InputStream ciphertextSource, byte[] associatedData)
      throws GeneralSecurityException, IOException;

  /**
   * Returns a wrapper around {@code ciphertextDestination}, such that any read-operation via the
   * wrapper results in AEAD-decryption of the underlying ciphertext, using {@code additionalData}
   * as additional authenticated data.
   *
   * <p>The returned InputStream may support {@code mark()}/{@code reset()}, but does not have to do
   * it -- {@code markSupported()} provides the corresponding info.
   *
   * <p>The returned InputStream supports {@code skip()}, yet possibly in an inefficient way, i.e.
   * by reading a sequence of blocks until the desired position. If a more efficient {@code
   * skip()}-functionality is needed, the Channel-based API can be used.
   */
  OutputStream newEncryptingStream(OutputStream ciphertextDestination, byte[] associatedData)
      throws GeneralSecurityException, IOException;
}
