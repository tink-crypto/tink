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

/** Tests for {@link SecretBytes}. */
@RunWith(JUnit4.class)
public final class SecretBytesTest {
  @Test
  public void testBasicWorks() throws Exception {
    byte[] plainArray = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};
    SecretBytes array = SecretBytes.copyFrom(plainArray, InsecureSecretKeyAccess.get());
    assertThat(array.toByteArray(InsecureSecretKeyAccess.get())).isEqualTo(plainArray);
  }

  @Test
  public void testSize() throws Exception {
    byte[] plainArray = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};
    SecretBytes array = SecretBytes.copyFrom(plainArray, InsecureSecretKeyAccess.get());
    assertThat(array.size()).isEqualTo(8);
  }

  @Test
  public void testSecretAccessNull_throws() throws Exception {
    byte[] plainArray = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};
    assertThrows(NullPointerException.class, () -> SecretBytes.copyFrom(plainArray, null));
  }

  @Test
  public void testSecretAccessNull_toByteArray_throws() throws Exception {
    SecretBytes array = SecretBytes.randomBytes(16);
    assertThrows(NullPointerException.class, () -> array.toByteArray(null));
  }

  @Test
  public void testImmutability_inputCopied() throws Exception {
    byte[] plainArray = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};
    SecretBytes array = SecretBytes.copyFrom(plainArray, InsecureSecretKeyAccess.get());
    plainArray[5] = 55;
    assertThat(array.toByteArray(InsecureSecretKeyAccess.get()))
        .isEqualTo(new byte[] {0, 1, 2, 3, 4, 5, 6, 7});
  }

  @Test
  public void testImmutability_outputCopied() throws Exception {
    byte[] plainArray = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};
    SecretBytes array = SecretBytes.copyFrom(plainArray, InsecureSecretKeyAccess.get());
    array.toByteArray(InsecureSecretKeyAccess.get())[5] = 55;
    assertThat(array.toByteArray(InsecureSecretKeyAccess.get()))
        .isEqualTo(new byte[] {0, 1, 2, 3, 4, 5, 6, 7});
  }

  @Test
  public void testEqualsSecretBytes_bitflips_different() throws Exception {
    SecretBytes array = SecretBytes.randomBytes(8);
    for (int i = 0; i < 8; ++i) {
      for (int j = 0; j < 8; ++j) {
        byte[] plainArray = array.toByteArray(InsecureSecretKeyAccess.get());
        plainArray[i] = (byte) (plainArray[i] ^ 1 << j);
        SecretBytes array2 = SecretBytes.copyFrom(plainArray, InsecureSecretKeyAccess.get());
        assertThat(array.equalsSecretBytes(array2)).isFalse();
      }
    }
  }

  @Test
  public void testEqualsSecretBytes_lengths_different() throws Exception {
    SecretBytes array = SecretBytes.randomBytes(16);
    for (int i = 0; i < 16; ++i) {
      byte[] shorterCopy = Arrays.copyOf(array.toByteArray(InsecureSecretKeyAccess.get()), i);
      SecretBytes array2 = SecretBytes.copyFrom(shorterCopy, InsecureSecretKeyAccess.get());
      assertThat(array.equalsSecretBytes(array2)).isFalse();
    }
  }

  @Test
  public void testEqualsSecretBytes_equals() throws Exception {
    SecretBytes array = SecretBytes.randomBytes(16);
    SecretBytes array2 =
        SecretBytes.copyFrom(
            array.toByteArray(InsecureSecretKeyAccess.get()), InsecureSecretKeyAccess.get());
    assertThat(array.equalsSecretBytes(array2)).isTrue();
  }

  @Test
  public void testRandomBytes_alwaysDifferent() throws Exception {
    SecretBytes array = SecretBytes.randomBytes(16);
    for (int i = 0; i < 100; ++i) {
      assertThat(array.equalsSecretBytes(SecretBytes.randomBytes(16))).isFalse();
    }
  }
}
