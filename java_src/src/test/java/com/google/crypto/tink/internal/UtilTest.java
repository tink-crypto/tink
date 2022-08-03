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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.util.Bytes;
import java.util.stream.IntStream;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for Tink internal Util class. */
@RunWith(JUnit4.class)
public final class UtilTest {

  @Test
  public void randKeyId_repeatedCallsShouldOutputDifferentValues() {
    assertThat(
            (int) IntStream.range(0, 4).map(unused -> Util.randKeyId()).boxed().distinct().count())
        .isAtLeast(2);
  }

  @Test
  public void toBytesFromPrintableAscii_works() throws Exception {
    String pureAsciiString =
        "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    Bytes pureAsciiBytes = Bytes.copyFrom(pureAsciiString.getBytes("ASCII"));
    assertThat(Util.toBytesFromPrintableAscii(pureAsciiString)).isEqualTo(pureAsciiBytes);
  }

  @Test
  public void toBytesFromPrintableAscii_nonAscii_throws() throws Exception {
    assertThrows(TinkBugException.class, () -> Util.toBytesFromPrintableAscii("\n"));
    assertThrows(TinkBugException.class, () -> Util.toBytesFromPrintableAscii(" "));
    assertThrows(TinkBugException.class, () -> Util.toBytesFromPrintableAscii("\0x7f"));
    assertThrows(TinkBugException.class, () -> Util.toBytesFromPrintableAscii("ö"));
  }

  @Test
  public void testGetAndroidApiLevel() throws Exception {
    try {
      Class<?> buildVersion = Class.forName("android.os.Build$VERSION");
      int expectedVersion = buildVersion.getDeclaredField("SDK_INT").getInt(null);
      assertThat(Util.getAndroidApiLevel()).isEqualTo(expectedVersion);
    } catch (ReflectiveOperationException e) {
      assertThat(Util.getAndroidApiLevel()).isEqualTo(null);
    }
  }
}
