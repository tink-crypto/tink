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

package com.google.cloud.crypto.tink;

import com.google.cloud.crypto.tink.TinkProto.Keyset.Key;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/**
 * Constants and convenience methods that deal with crypto format.
 */
public final class CryptoFormat {

  /**
   * Prefix size of Tink and Legacy key types.
   */
  public static final int NON_RAW_PREFIX_SIZE = 5;

  /**
   * Legacy prefix starts with \x00 and followed by a 4-byte key id.
   */
  public static final int LEGACY_PREFIX_SIZE = NON_RAW_PREFIX_SIZE;
  public static final byte LEGACY_START_BYTE = (byte) 0;

  /**
   * Tink prefix starts with \x01 and followed by a 4-byte key id.
   */
  public static final int TINK_PREFIX_SIZE = NON_RAW_PREFIX_SIZE;
  public static final byte TINK_START_BYTE = (byte) 1;

  /**
   * Raw prefix is empty.
   */
  public static final int RAW_PREFIX_SIZE = 0;
  public static final byte[] RAW_PREFIX = new byte[0];

  /**
   * Convenience method for generating the prefix of all ciphertexts or signatures
   * produced by the specified {@code key}.
   *
   * @throws GeneralSecurityException if the prefix type of {@code key} is unknown.
   * @return a prefix.
   */
  public static byte[] getOutputPrefix(Key key) throws GeneralSecurityException {
    switch (key.getOutputPrefixType()) {
      case LEGACY:
        return ByteBuffer.allocate(LEGACY_PREFIX_SIZE)
            .put(LEGACY_START_BYTE)
            .putInt(key.getKeyId())
            .array();
      case TINK:
        return ByteBuffer.allocate(TINK_PREFIX_SIZE)
            .put(TINK_START_BYTE)
            .putInt(key.getKeyId())
            .array();
      case RAW:
        return RAW_PREFIX;
      default:
        throw new GeneralSecurityException("unknown output prefix type");
    }
  }
}
