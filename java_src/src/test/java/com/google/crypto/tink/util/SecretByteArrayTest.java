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

package com.google.crypto.tink.util;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link SecretByteArray}. */
@RunWith(JUnit4.class)
public final class SecretByteArrayTest {
  @Test
  public void testBasicWorks() throws Exception {
    byte[] plainArray = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};
    SecretByteArray array = SecretByteArray.copyOf(plainArray, InsecureSecretKeyAccess.get());
    assertThat(array.getBytes(InsecureSecretKeyAccess.get())).isEqualTo(plainArray);
  }

  @Test
  public void testGetLength() throws Exception {
    byte[] plainArray = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};
    SecretByteArray array = SecretByteArray.copyOf(plainArray, InsecureSecretKeyAccess.get());
    assertThat(array.getLength()).isEqualTo(8);
  }

  @Test
  public void testSecretAccessNull_throws() throws Exception {
    byte[] plainArray = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};
    assertThrows(NullPointerException.class, () -> SecretByteArray.copyOf(plainArray, null));
  }

  @Test
  public void testSecretAccessNull_getBytes_throws() throws Exception {
    SecretByteArray array = SecretByteArray.randomBytes(16);
    assertThrows(NullPointerException.class, () -> array.getBytes(null));
  }

  @Test
  public void testImmutability_inputCopied() throws Exception {
    byte[] plainArray = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};
    SecretByteArray array = SecretByteArray.copyOf(plainArray, InsecureSecretKeyAccess.get());
    plainArray[5] = 55;
    assertThat(array.getBytes(InsecureSecretKeyAccess.get()))
        .isEqualTo(new byte[] {0, 1, 2, 3, 4, 5, 6, 7});
  }

  @Test
  public void testImmutability_outputCopied() throws Exception {
    byte[] plainArray = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};
    SecretByteArray array = SecretByteArray.copyOf(plainArray, InsecureSecretKeyAccess.get());
    array.getBytes(InsecureSecretKeyAccess.get())[5] = 55;
    assertThat(array.getBytes(InsecureSecretKeyAccess.get()))
        .isEqualTo(new byte[] {0, 1, 2, 3, 4, 5, 6, 7});
  }

  @Test
  public void testEqualsSecretByteArray_bitflips_different() throws Exception {
    SecretByteArray array = SecretByteArray.randomBytes(8);
    for (int i = 0; i < 8; ++i) {
      for (int j = 0; j < 8; ++j) {
        byte[] plainArray = array.getBytes(InsecureSecretKeyAccess.get());
        plainArray[i] = (byte) (plainArray[i] ^ 1 << j);
        SecretByteArray array2 = SecretByteArray.copyOf(plainArray, InsecureSecretKeyAccess.get());
        assertThat(array.equalsSecretByteArray(array2)).isFalse();
      }
    }
  }

  @Test
  public void testEqualsSecretByteArray_lengths_different() throws Exception {
    SecretByteArray array = SecretByteArray.randomBytes(16);
    for (int i = 0; i < 16; ++i) {
      byte[] shorterCopy = Arrays.copyOf(array.getBytes(InsecureSecretKeyAccess.get()), i);
      SecretByteArray array2 = SecretByteArray.copyOf(shorterCopy, InsecureSecretKeyAccess.get());
      assertThat(array.equalsSecretByteArray(array2)).isFalse();
    }
  }

  @Test
  public void testEqualsSecretByteArray_equals() throws Exception {
    SecretByteArray array = SecretByteArray.randomBytes(16);
    SecretByteArray array2 =
        SecretByteArray.copyOf(
            array.getBytes(InsecureSecretKeyAccess.get()), InsecureSecretKeyAccess.get());
    assertThat(array.equalsSecretByteArray(array2)).isTrue();
  }

  @Test
  public void testRandomBytes_alwaysDifferent() throws Exception {
    SecretByteArray array = SecretByteArray.randomBytes(16);
    for (int i = 0; i < 100; ++i) {
      assertThat(array.equalsSecretByteArray(SecretByteArray.randomBytes(16))).isFalse();
    }
  }
}
