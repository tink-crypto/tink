// Copyright 2022 Google LLC
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

import static com.google.common.truth.Truth.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class Base64Test {
  @Test
  public void testEncode_testVectors() {
    assertThat(Base64.encode(new byte[] {})).isEqualTo("");
    assertThat(Base64.encode(new byte[] {0})).isEqualTo("AA==");
    assertThat(Base64.encode(new byte[] {0, 0})).isEqualTo("AAA=");
    assertThat(Base64.encode(new byte[] {0, 0, 0})).isEqualTo("AAAA");
    assertThat(Base64.encode(new byte[] {0, 0, 25})).isEqualTo("AAAZ");
    assertThat(Base64.encode(new byte[] {0, 0, 26})).isEqualTo("AAAa");
    assertThat(Base64.encode(new byte[] {0, 0, 51})).isEqualTo("AAAz");
    assertThat(Base64.encode(new byte[] {0, 0, 52})).isEqualTo("AAA0");
    assertThat(Base64.encode(new byte[] {0, 0, 61})).isEqualTo("AAA9");
    assertThat(Base64.encode(new byte[] {0, 0, 62})).isEqualTo("AAA+");
    assertThat(Base64.encode(new byte[] {0, 0, 63})).isEqualTo("AAA/");
    assertThat(Base64.encode(new byte[] {0, 0, 64})).isEqualTo("AABA");
  }

  @Test
  public void testUrlSafeEncode_testVectors() {
    assertThat(Base64.urlSafeEncode(new byte[] {})).isEqualTo("");
    assertThat(Base64.urlSafeEncode(new byte[] {0})).isEqualTo("AA");
    assertThat(Base64.urlSafeEncode(new byte[] {0, 0})).isEqualTo("AAA");
    assertThat(Base64.urlSafeEncode(new byte[] {0, 0, 0})).isEqualTo("AAAA");
    assertThat(Base64.urlSafeEncode(new byte[] {0, 0, 25})).isEqualTo("AAAZ");
    assertThat(Base64.urlSafeEncode(new byte[] {0, 0, 26})).isEqualTo("AAAa");
    assertThat(Base64.urlSafeEncode(new byte[] {0, 0, 51})).isEqualTo("AAAz");
    assertThat(Base64.urlSafeEncode(new byte[] {0, 0, 52})).isEqualTo("AAA0");
    assertThat(Base64.urlSafeEncode(new byte[] {0, 0, 61})).isEqualTo("AAA9");
    assertThat(Base64.urlSafeEncode(new byte[] {0, 0, 62})).isEqualTo("AAA-");
    assertThat(Base64.urlSafeEncode(new byte[] {0, 0, 63})).isEqualTo("AAA_");
    assertThat(Base64.urlSafeEncode(new byte[] {0, 0, 64})).isEqualTo("AABA");
  }

  @Test
  public void testEncode_noPadding() throws Exception {
    assertThat(Base64.encode(new byte[] {}, Base64.NO_PADDING)).isEqualTo(new byte[]{});
    assertThat(Base64.encode(new byte[] {0}, Base64.NO_PADDING))
        .isEqualTo("AA\n".getBytes("UTF-8"));
    assertThat(Base64.encode(new byte[] {0, 0}, Base64.NO_PADDING))
        .isEqualTo("AAA\n".getBytes("UTF-8"));
  }

  @Test
  public void testEncode_flags() throws Exception {
    // 114 = 19 * 3 * 2 -> when encoded: 19 * 4 * 2 -- hence 2 lines at 19 * 4 characters
    byte[] longByteArray = new byte[114];

    String singleLine =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assertThat(Base64.encode(longByteArray, Base64.DEFAULT))
        .isEqualTo((singleLine + "\n" + singleLine + "\n").getBytes("UTF-8"));
    assertThat(Base64.encode(longByteArray, Base64.NO_WRAP))
        .isEqualTo((singleLine + singleLine).getBytes("UTF-8"));
    assertThat(Base64.encode(longByteArray, Base64.CRLF))
        .isEqualTo((singleLine + "\r\n" + singleLine + "\r\n").getBytes("UTF-8"));
  }

  @Test
  public void testDecode_testVectors() {
    assertThat(Base64.decode("")).isEqualTo(new byte[] {});
    assertThat(Base64.decode("AA==")).isEqualTo(new byte[] {0});
    assertThat(Base64.decode("AAA=")).isEqualTo(new byte[] {0, 0});
    assertThat(Base64.decode("AAAA")).isEqualTo(new byte[] {0, 0, 0});
    assertThat(Base64.decode("AAAZ")).isEqualTo(new byte[] {0, 0, 25});
    assertThat(Base64.decode("AAAa")).isEqualTo(new byte[] {0, 0, 26});
    assertThat(Base64.decode("AAAz")).isEqualTo(new byte[] {0, 0, 51});
    assertThat(Base64.decode("AAA0")).isEqualTo(new byte[] {0, 0, 52});
    assertThat(Base64.decode("AAA9")).isEqualTo(new byte[] {0, 0, 61});
    assertThat(Base64.decode("AAA+")).isEqualTo(new byte[] {0, 0, 62});
    assertThat(Base64.decode("AAA/")).isEqualTo(new byte[] {0, 0, 63});
    assertThat(Base64.decode("AABA")).isEqualTo(new byte[] {0, 0, 64});
  }

  @Test
  public void testUrlSafeDecode_testVectors() {
    assertThat(Base64.urlSafeDecode("")).isEqualTo(new byte[] {});
    assertThat(Base64.urlSafeDecode("AA")).isEqualTo(new byte[] {0});
    assertThat(Base64.urlSafeDecode("AAA")).isEqualTo(new byte[] {0, 0});
    assertThat(Base64.urlSafeDecode("AAAA")).isEqualTo(new byte[] {0, 0, 0});
    assertThat(Base64.urlSafeDecode("AAAZ")).isEqualTo(new byte[] {0, 0, 25});
    assertThat(Base64.urlSafeDecode("AAAa")).isEqualTo(new byte[] {0, 0, 26});
    assertThat(Base64.urlSafeDecode("AAAz")).isEqualTo(new byte[] {0, 0, 51});
    assertThat(Base64.urlSafeDecode("AAA0")).isEqualTo(new byte[] {0, 0, 52});
    assertThat(Base64.urlSafeDecode("AAA9")).isEqualTo(new byte[] {0, 0, 61});
    assertThat(Base64.urlSafeDecode("AAA-")).isEqualTo(new byte[] {0, 0, 62});
    assertThat(Base64.urlSafeDecode("AAA_")).isEqualTo(new byte[] {0, 0, 63});
    assertThat(Base64.urlSafeDecode("AABA")).isEqualTo(new byte[] {0, 0, 64});
  }

  @Test
  public void testDecode_flags() throws Exception {
    // 114 = 19 * 3 * 2 -> when encoded: 19 * 4 * 2 -- hence 2 lines at 19 * 4 characters
    byte[] longByteArray = new byte[114];

    String singleLine =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assertThat(
            Base64.decode(
                (singleLine + "\n" + singleLine + "\n").getBytes("UTF-8"), Base64.DEFAULT))
        .isEqualTo(longByteArray);
    assertThat(Base64.decode((singleLine + singleLine).getBytes("UTF-8"), Base64.NO_WRAP))
        .isEqualTo(longByteArray);
    assertThat(
            Base64.decode(
                (singleLine + "\r\n" + singleLine + "\r\n").getBytes("UTF-8"), Base64.CRLF))
        .isEqualTo(longByteArray);
  }

  // TODO(b/238096965) Add more tests.
}
