// Copyright 2024 Google LLC
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
package com.google.crypto.tink.hybrid.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class HpkeUtilTest {

  @Test
  public void intToByteArray_works() {
    assertThat(HpkeUtil.intToByteArray(0, 0)).isEqualTo(new byte[] {});
    assertThat(HpkeUtil.intToByteArray(1, 42)).isEqualTo(new byte[] {(byte) 42});
    assertThat(HpkeUtil.intToByteArray(2, 0x0102)).isEqualTo(new byte[] {(byte) 01, (byte) 0x02});

    assertThat(HpkeUtil.intToByteArray(1, 0xaa)).isEqualTo(new byte[] {(byte) 0xaa});
    assertThat(HpkeUtil.intToByteArray(1, 256 - 1)).isEqualTo(new byte[] {(byte) 0xff});
    assertThat(HpkeUtil.intToByteArray(2, 0xaabb)).isEqualTo(new byte[] {(byte) 0xaa, (byte) 0xbb});
    assertThat(HpkeUtil.intToByteArray(2, 256 * 256 - 1))
        .isEqualTo(new byte[] {(byte) 0xff, (byte) 0xff});
    assertThat(HpkeUtil.intToByteArray(3, 0xaabbcc))
        .isEqualTo(new byte[] {(byte) 0xaa, (byte) 0xbb, (byte) 0xcc});
    assertThat(HpkeUtil.intToByteArray(3, 256 * 256 * 256 - 1))
        .isEqualTo(new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff});
    assertThat(HpkeUtil.intToByteArray(4, 0x0abbccdd))
        .isEqualTo(new byte[] {(byte) 0x0a, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd});
    assertThat(HpkeUtil.intToByteArray(4, Integer.MAX_VALUE))
        .isEqualTo(new byte[] {(byte) 0x7f, (byte) 0xff, (byte) 0xff, (byte) 0xff});
  }

  @Test
  public void intToByteArray_failsWithInvalidCapacity() {
    assertThrows(IllegalArgumentException.class, () -> HpkeUtil.intToByteArray(5, 0));
    assertThrows(IllegalArgumentException.class, () -> HpkeUtil.intToByteArray(-1, 0));
  }

  @Test
  public void intToByteArray_valueTooLong_fails() {
    assertThrows(IllegalArgumentException.class, () -> HpkeUtil.intToByteArray(0, 1));
    assertThrows(IllegalArgumentException.class, () -> HpkeUtil.intToByteArray(0, -1));
    assertThrows(IllegalArgumentException.class, () -> HpkeUtil.intToByteArray(1, 256));
    assertThrows(IllegalArgumentException.class, () -> HpkeUtil.intToByteArray(1, -1));
    assertThrows(IllegalArgumentException.class, () -> HpkeUtil.intToByteArray(2, 256 * 256));
    assertThrows(IllegalArgumentException.class, () -> HpkeUtil.intToByteArray(2, -1));
    assertThrows(IllegalArgumentException.class, () -> HpkeUtil.intToByteArray(3, 256 * 256 * 256));
    assertThrows(IllegalArgumentException.class, () -> HpkeUtil.intToByteArray(3, -1));
    assertThrows(IllegalArgumentException.class, () -> HpkeUtil.intToByteArray(4, -1));
    assertThrows(
        IllegalArgumentException.class, () -> HpkeUtil.intToByteArray(4, Integer.MIN_VALUE));
  }
}
