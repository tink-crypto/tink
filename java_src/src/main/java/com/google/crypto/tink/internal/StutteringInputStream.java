// Copyright 2023 Google LLC
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

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * An implementation of ByteArrayInputStream which returns each element separately. Used for testing
 * only.
 */
public final class StutteringInputStream extends InputStream {
  private final byte[] result;
  private int pos = 0;

  private StutteringInputStream(byte[] b) {
    result = b;
  }

  public static StutteringInputStream copyFrom(byte[] b) {
    return new StutteringInputStream(Arrays.copyOf(b, b.length));
  }

  @Override
  public int read() throws IOException {
    if (pos >= result.length) {
      return -1;
    }
    int r = result[pos] & 0xFF;
    pos++;
    return r;
  }

  /**
   * We override this because the default always fills b[] but this is not guaranteed by the
   * interface.
   */
  @Override
  public int read(byte[] b, int off, int len) throws IOException {
    if (len == 0) {
      return 0;
    }
    int result = read();
    if (result == -1) {
      return -1;
    }
    b[off] = (byte) result;
    return 1;
  }
}
