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

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/**
 * StreamSegmentEncrypter is a helper class that encrypts individual segments of a stream.
 *
 * <p>Instances of this interfaces are passed to ...EncryptingChannel. Each instance of a segment
 * encrypter is used to encrypt one stream. Typically, constructing a new StreamSegmentEncrypter
 * results in the generation of a new symmetric key. This new symmetric key is used to encrypt the
 * segments of the stream. The key itself wrapped with or derived from the key from StreamingAead
 * instance. The wrapped key or the salt used to derive the symmetric key is part of the header.
 *
 * <p>A StreamSegmentEncrypter has a state: it keeps the number of segments encrypted so far. This
 * state is used to encrypt each segment with different parameters, so that segments in the
 * ciphertext cannot be switched.
 *
 * @since 1.1.0
 */
public interface StreamSegmentEncrypter {

  /**
   * Returns the header of the ciphertext stream.
   */
  ByteBuffer getHeader();

  /**
   * Encrypts the next plaintext segment.
   * This uses encryptedSegments as the segment number for the encryption.
   */
  void encryptSegment(
      ByteBuffer plaintext,
      boolean isLastSegment,
      ByteBuffer ciphertext)
      throws GeneralSecurityException;

  /**
   * Encrypt a segment consisting of two parts.
   * This method simplifies the case where one part of the plaintext is buffered and the other part
   * is passed in by the caller.
   */
  void encryptSegment(
        ByteBuffer part1,
        ByteBuffer part2,
        boolean isLastSegment,
        ByteBuffer ciphertext)
        throws GeneralSecurityException;

  int getEncryptedSegments();
}

