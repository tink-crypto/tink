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

package com.google.crypto.tink.internal;

import com.google.crypto.tink.subtle.Hex;
import com.google.errorprone.annotations.Immutable;
import java.util.Arrays;

/**
 * Immutable Wrapper around a byte array.
 *
 * <p>Wrap a bytearray so it prevents callers from modifying its contents. It does this by making a
 * copy upon initialization, and also makes a copy if the underlying bytes are requested.
 *
 * @since 1.0.0
 */
@Immutable
public final class Bytes {
  /**
   * @param data the byte array to be wrapped.
   * @return an immutable wrapper around the provided bytes.
   */
  public static Bytes copyFrom(final byte[] data) {
    if (data == null) {
      return null;
    } else {
      return copyFrom(data, 0, data.length);
    }
  }

  /**
   * Wrap an immutable byte array over a slice of a Bytes
   *
   * @param data the byte array to be wrapped.
   * @param start the starting index of the slice
   * @param len the length of the slice. start + len must be less than the length of the array.
   * @return an immutable wrapper around the bytes in the slice from {@code start} to {@code start +
   *     len}
   */
  public static Bytes copyFrom(final byte[] data, final int start, final int len) {
    return new Bytes(data, start, len);
  }

  /**
   * @return a copy of the bytes wrapped by this object.
   */
  public byte[] toByteArray() {
    byte[] result = new byte[data.length];
    System.arraycopy(data, 0, result, 0, data.length);
    return result;
  }

  /**
   * @return the length of the bytes wrapped by this object.
   */
  public int size() {
    return data.length;
  }

  private Bytes(final byte[] buf, final int start, final int len) {
    data = new byte[len];
    System.arraycopy(buf, start, data, 0, len);
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof Bytes)) {
      return false;
    }
    Bytes other = (Bytes) o;
    return Arrays.equals(other.data, data);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(data);
  }

  @Override
  public String toString() {
    return "Bytes(" + Hex.encode(data) + ")";
  }

  @SuppressWarnings("Immutable") // We copy the data on input and output.
  private final byte[] data;
}
