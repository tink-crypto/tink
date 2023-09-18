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
import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.io.InputStream;
import java.security.GeneralSecurityException;
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
  public void randKeyId_repeatedCallsShouldOutputANegativeValue() {
    assertThat(IntStream.range(0, 100).map(unused -> Util.randKeyId()).min().getAsInt())
        .isAtMost(0);
  }

  @Test
  public void toBytesFromPrintableAscii_works() throws Exception {
    String pureAsciiString =
        "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    Bytes pureAsciiBytes = Bytes.copyFrom(pureAsciiString.getBytes(US_ASCII));
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
  public void checkedToBytesFromPrintableAscii_works() throws Exception {
    String pureAsciiString =
        "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    Bytes pureAsciiBytes = Bytes.copyFrom(pureAsciiString.getBytes("ASCII"));
    assertThat(Util.checkedToBytesFromPrintableAscii(pureAsciiString)).isEqualTo(pureAsciiBytes);
  }

  @Test
  public void checkedToBytesFromPrintableAscii_nonAscii_throws() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> Util.checkedToBytesFromPrintableAscii("\n"));
    assertThrows(GeneralSecurityException.class, () -> Util.checkedToBytesFromPrintableAscii(" "));
    assertThrows(
        GeneralSecurityException.class, () -> Util.checkedToBytesFromPrintableAscii("\0x7f"));
    assertThrows(GeneralSecurityException.class, () -> Util.checkedToBytesFromPrintableAscii("ö"));
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

  @Test
  public void testIsAndroid() throws Exception {
    try {
      Class<?> buildVersion = Class.forName("android.os.Build$VERSION");
      assertThat(Util.isAndroid()).isTrue();
    } catch (ReflectiveOperationException e) {
      assertThat(Util.isAndroid()).isFalse();
    }
  }

  @Test
  public void testIsPrefix() throws Exception {
    assertTrue(Util.isPrefix(new byte[] {1, 2, 3}, new byte[] {1, 2, 3, 4, 5}));
    assertTrue(Util.isPrefix(new byte[] {}, new byte[] {1, 2, 3, 4, 5}));
    assertTrue(Util.isPrefix(new byte[] {}, new byte[] {}));
    assertTrue(Util.isPrefix(new byte[] {5, 7, 9}, new byte[] {5, 7, 9}));

    assertFalse(Util.isPrefix(new byte[] {5, 7, 9, 10}, new byte[] {5, 7, 9}));
    assertFalse(Util.isPrefix(new byte[] {5, 7, 10}, new byte[] {5, 7, 9}));
    assertFalse(Util.isPrefix(new byte[] {1}, new byte[] {}));
  }

  @Test
  public void readIntoSecretBytes_works() throws Exception {
    InputStream fragmentedInputStream =
        new InputStream() {
          byte nextNumber = 4;

          @Override
          public int read() {
            return 0;
          }

          @Override
          public int read(byte[] b, int off, int len) {
            b[off] = nextNumber;
            nextNumber++;
            return 1;
          }
        };
    SecretBytes result =
        Util.readIntoSecretBytes(fragmentedInputStream, 4, InsecureSecretKeyAccess.get());

    assertThat(result.toByteArray(InsecureSecretKeyAccess.get()))
        .isEqualTo(new byte[] {4, 5, 6, 7});

    result = Util.readIntoSecretBytes(fragmentedInputStream, 4, InsecureSecretKeyAccess.get());
    assertThat(result.toByteArray(InsecureSecretKeyAccess.get()))
        .isEqualTo(new byte[] {8, 9, 10, 11});
  }

  @Test
  public void readIntoSecretBytes_throwsOnNotEnoughPseudorandomness() throws Exception {
    byte randomness = 4;
    InputStream shortInputStream =
        new InputStream() {
          int numReads = 3;

          @Override
          public int read() {
            return 0;
          }

          @Override
          public int read(byte[] b, int off, int len) {
            if (numReads == 0) {
              return -1;
            }
            --numReads;
            b[off] = randomness;
            return 1;
          }
        };
    assertThrows(
        GeneralSecurityException.class,
        () -> Util.readIntoSecretBytes(shortInputStream, 4, InsecureSecretKeyAccess.get()));
  }
}
