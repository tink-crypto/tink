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

package com.google.crypto.tink.util;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link Bytes} */
@RunWith(JUnit4.class)
public class BytesTest {
  @Test
  public void testBasicWorks() throws Exception {
    byte[] plainArray = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};
    Bytes array = Bytes.copyFrom(plainArray);
    assertThat(array.toByteArray()).isEqualTo(plainArray);
  }

  @Test
  public void testWithRange() throws Exception {
    byte[] plainArray = new byte[] {100, 100, 100, 0, 1, 2, 3, 4, 5, 6, 7, 100, 100, 100};
    Bytes array = Bytes.copyFrom(plainArray, 3, 8);
    assertThat(array.toByteArray()).isEqualTo(new byte[] {0, 1, 2, 3, 4, 5, 6, 7});
  }

  @Test
  public void testGetLength() throws Exception {
    byte[] plainArray = new byte[] {100, 100, 100, 0, 1, 2, 3, 4, 5, 6, 7, 100, 100, 100};
    Bytes array = Bytes.copyFrom(plainArray, 3, 8);
    assertThat(array.size()).isEqualTo(8);
  }

  @Test
  public void testImmutability_inputCopied1() throws Exception {
    byte[] plainArray = new byte[] {100, 100, 100, 0, 1, 2, 3, 4, 5, 6, 7, 100, 100, 100};
    Bytes array = Bytes.copyFrom(plainArray, 3, 8);
    plainArray[5] = 55;
    assertThat(array.toByteArray()).isEqualTo(new byte[] {0, 1, 2, 3, 4, 5, 6, 7});
  }

  @Test
  public void testImmutability_inputCopied2() throws Exception {
    byte[] plainArray = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};
    Bytes array = Bytes.copyFrom(plainArray);
    plainArray[5] = 55;
    assertThat(array.toByteArray()).isEqualTo(new byte[] {0, 1, 2, 3, 4, 5, 6, 7});
  }

  @Test
  public void testImmutability_outputCopied() throws Exception {
    byte[] plainArray = new byte[] {100, 100, 100, 0, 1, 2, 3, 4, 5, 6, 7, 100, 100, 100};
    Bytes array = Bytes.copyFrom(plainArray, 3, 8);
    array.toByteArray()[5] = 55;
    assertThat(array.toByteArray()).isEqualTo(new byte[] {0, 1, 2, 3, 4, 5, 6, 7});
  }

  @Test
  public void testEquals() throws Exception {
    byte[] plainArray = new byte[] {1, 2, 3, 1, 2, 3};
    Bytes byteArray = Bytes.copyFrom(plainArray);
    assertThat(byteArray.equals(byteArray)).isTrue();
    assertThat(byteArray.equals(Bytes.copyFrom(plainArray))).isTrue();

    assertThat(byteArray.equals(Bytes.copyFrom(plainArray, 0, 5))).isFalse();
    assertThat(byteArray.equals(Bytes.copyFrom(plainArray, 1, 5))).isFalse();

    assertThat(Bytes.copyFrom(plainArray, 0, 3).equals(Bytes.copyFrom(plainArray, 3, 3))).isTrue();
  }

  @Test
  @SuppressWarnings("EqualsIncompatibleType")
  public void testEquals_differentObject() throws Exception {
    assertThat(Bytes.copyFrom(new byte[] {}).equals(new Integer(0))).isFalse();
  }

  @Test
  public void testHashCode() throws Exception {
    byte[] plainArray = new byte[] {1, 2, 3, 1, 2, 3};
    Bytes byteArray = Bytes.copyFrom(plainArray);
    assertThat(byteArray.hashCode()).isEqualTo(Bytes.copyFrom(plainArray).hashCode());

    assertThat(Bytes.copyFrom(plainArray, 0, 3).hashCode())
        .isEqualTo(Bytes.copyFrom(plainArray, 3, 3).hashCode());
  }

  @Test
  public void testHashCode_notAlwaysTheSame() throws Exception {
    int hashCode = Bytes.copyFrom(new byte[] {0}).hashCode();
    byte b = 1;
    while (Bytes.copyFrom(new byte[] {(byte) b}).hashCode() == hashCode && b != 0) {
      b++;
    }
    assertThat(Bytes.copyFrom(new byte[] {(byte) b}).hashCode()).isNotEqualTo(hashCode);
  }

  @Test
  public void testCopyFrom_null_throwsNPE() throws Exception {
    assertThrows(NullPointerException.class, () -> Bytes.copyFrom(null));
    assertThrows(NullPointerException.class, () -> Bytes.copyFrom(null, 0, 0));
  }
}
