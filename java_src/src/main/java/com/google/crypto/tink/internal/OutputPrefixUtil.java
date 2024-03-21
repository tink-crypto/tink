// Copyright 2024 Google Inc.
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

package com.google.crypto.tink.internal;

import com.google.crypto.tink.util.Bytes;
import java.nio.ByteBuffer;

/** Convenience functions that deal with output prefix. */
public final class OutputPrefixUtil {

  /** All non-empty prefixes must have the same size of 5 bytes. */
  public static final int NON_EMPTY_PREFIX_SIZE = 5;

  public static final byte LEGACY_START_BYTE = (byte) 0;

  public static final byte TINK_START_BYTE = (byte) 1;

  public static final Bytes EMPTY_PREFIX = Bytes.copyFrom(new byte[0]);

  public static final Bytes getLegacyOutputPrefix(int keyId) {
    return Bytes.copyFrom(
        ByteBuffer.allocate(NON_EMPTY_PREFIX_SIZE) // BIG_ENDIAN by default
            .put(LEGACY_START_BYTE)
            .putInt(keyId)
            .array());
  }

  public static final Bytes getTinkOutputPrefix(int keyId) {
    return Bytes.copyFrom(
        ByteBuffer.allocate(NON_EMPTY_PREFIX_SIZE) // BIG_ENDIAN by default
            .put(TINK_START_BYTE)
            .putInt(keyId)
            .array());
  }

  private OutputPrefixUtil() {}
}
