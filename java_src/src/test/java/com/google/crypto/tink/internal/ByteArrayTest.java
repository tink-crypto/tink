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

import static com.google.common.truth.Truth.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link ByteArray} */
@RunWith(JUnit4.class)
public class ByteArrayTest {
  @Test
  public void testBasicWorks() throws Exception {
    byte[] plainArray = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};
    ByteArray array = ByteArray.copyFrom(plainArray);
    assertThat(array.toByteArray()).isEqualTo(plainArray);
  }

  @Test
  public void testWithRange() throws Exception {
    byte[] plainArray = new byte[] {100, 100, 100, 0, 1, 2, 3, 4, 5, 6, 7, 100, 100, 100};
    ByteArray array = ByteArray.copyFrom(plainArray, 3, 8);
    assertThat(array.toByteArray()).isEqualTo(new byte[] {0, 1, 2, 3, 4, 5, 6, 7});
  }

  @Test
  public void testGetLength() throws Exception {
    byte[] plainArray = new byte[] {100, 100, 100, 0, 1, 2, 3, 4, 5, 6, 7, 100, 100, 100};
    ByteArray array = ByteArray.copyFrom(plainArray, 3, 8);
    assertThat(array.size()).isEqualTo(8);
  }

  @Test
  public void testImmutability_inputCopied1() throws Exception {
    byte[] plainArray = new byte[] {100, 100, 100, 0, 1, 2, 3, 4, 5, 6, 7, 100, 100, 100};
    ByteArray array = ByteArray.copyFrom(plainArray, 3, 8);
    plainArray[5] = 55;
    assertThat(array.toByteArray()).isEqualTo(new byte[] {0, 1, 2, 3, 4, 5, 6, 7});
  }

  @Test
  public void testImmutability_inputCopied2() throws Exception {
    byte[] plainArray = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};
    ByteArray array = ByteArray.copyFrom(plainArray);
    plainArray[5] = 55;
    assertThat(array.toByteArray()).isEqualTo(new byte[] {0, 1, 2, 3, 4, 5, 6, 7});
  }

  @Test
  public void testImmutability_outputCopied() throws Exception {
    byte[] plainArray = new byte[] {100, 100, 100, 0, 1, 2, 3, 4, 5, 6, 7, 100, 100, 100};
    ByteArray array = ByteArray.copyFrom(plainArray, 3, 8);
    array.toByteArray()[5] = 55;
    assertThat(array.toByteArray()).isEqualTo(new byte[] {0, 1, 2, 3, 4, 5, 6, 7});
  }

  @Test
  public void testEquals() throws Exception {
    byte[] plainArray = new byte[] {1, 2, 3, 1, 2, 3};
    ByteArray byteArray = ByteArray.copyFrom(plainArray);
    assertThat(byteArray.equals(byteArray)).isTrue();
    assertThat(byteArray.equals(ByteArray.copyFrom(plainArray))).isTrue();

    assertThat(byteArray.equals(ByteArray.copyFrom(plainArray, 0, 5))).isFalse();
    assertThat(byteArray.equals(ByteArray.copyFrom(plainArray, 1, 5))).isFalse();

    assertThat(ByteArray.copyFrom(plainArray, 0, 3).equals(ByteArray.copyFrom(plainArray, 3, 3)))
        .isTrue();
  }

  @Test
  @SuppressWarnings("EqualsIncompatibleType")
  public void testEquals_differentObject() throws Exception {
    assertThat(ByteArray.copyFrom(new byte[] {}).equals(new Integer(0))).isFalse();
  }

  @Test
  public void testHashCode() throws Exception {
    byte[] plainArray = new byte[] {1, 2, 3, 1, 2, 3};
    ByteArray byteArray = ByteArray.copyFrom(plainArray);
    assertThat(byteArray.hashCode()).isEqualTo(ByteArray.copyFrom(plainArray).hashCode());

    assertThat(ByteArray.copyFrom(plainArray, 0, 3).hashCode())
        .isEqualTo(ByteArray.copyFrom(plainArray, 3, 3).hashCode());
  }

  @Test
  public void testHashCode_notAlwaysTheSame() throws Exception {
    int hashCode = ByteArray.copyFrom(new byte[] {0}).hashCode();
    byte b = 1;
    while (ByteArray.copyFrom(new byte[] {(byte) b}).hashCode() == hashCode && b != 0) {
      b++;
    }
    assertThat(ByteArray.copyFrom(new byte[] {(byte) b}).hashCode()).isNotEqualTo(hashCode);
  }
}
