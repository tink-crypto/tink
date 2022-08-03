// Copyright 2021 Google LLC
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
import java.security.SecureRandom;
import javax.annotation.Nullable;

/** Helper functions used throughout Tink, for Tink internal use only. */
public final class Util {

  /** Returns a positive random int which can be used as a key ID in a keyset. */
  public static int randKeyId() {
    SecureRandom secureRandom = new SecureRandom();
    byte[] rand = new byte[4];
    int result = 0;
    while (result == 0) {
      secureRandom.nextBytes(rand);
      // TODO(b/148124847): Other languages create key_ids with the MSB set, so we should here too.
      result =
          ((rand[0] & 0x7f) << 24)
              | ((rand[1] & 0xff) << 16)
              | ((rand[2] & 0xff) << 8)
              | (rand[3] & 0xff);
    }
    return result;
  }

  private static final byte toByteFromPrintableAscii(char c) {
    if (c < '!' || c > '~') {
      throw new TinkBugException("Not a printable ASCII character: " + c);
    }
    return (byte) c;
  }

  /**
   * Converts a string {@code s} to a corresponding {@link Bytes} object.
   *
   * <p>The string must contain only printable ASCII characters; calling it in any other way is a
   * considered a bug in Tink. Spaces are not allowed.
   *
   * @throws TinkBugException if s contains a character which is not a printable ASCII character.
   */
  public static final Bytes toBytesFromPrintableAscii(String s) {
    byte[] result = new byte[s.length()];
    for (int i = 0; i < s.length(); ++i) {
      result[i] = toByteFromPrintableAscii(s.charAt(i));
    }
    return Bytes.copyFrom(result);
  }

  /** Returns the current Andrdoid API level as integer or null if we do not run on Android. */
  @Nullable
  public static Integer getAndroidApiLevel() {
    return BuildDispatchedCode.getApiLevel();
  }

  private Util() {}
}
