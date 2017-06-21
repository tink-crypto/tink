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

package com.google.crypto.tink.subtle;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.crypto.tink.TestUtil;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.Test;

/**
 * Base unit test class for DjbCiphers.
 */
public abstract class DjbCipherTestBase<T extends DjbCipher> {

  protected abstract T createInstance(byte[] key);

  static int[] twosCompInt(long[] a) {
    int[] ret = new int[a.length];
    for (int i = 0; i < a.length; i++) {
      ret[i] = (int) (a[i] - (a[i] > Integer.MAX_VALUE ? (1L << 32) : 0));
    }
    return ret;
  }

  static byte[] twosCompByte(int[] a) {
    byte[] ret = new byte[a.length];
    for (int i = 0; i < a.length; i++) {
      ret[i] = (byte) (a[i] - (a[i] > Byte.MAX_VALUE ? (1 << 8) : 0));
    }
    return ret;
  }

  @Test
  public void testRandomInputs() throws GeneralSecurityException {
    for (int i = 0; i < 1000; i++) {
      byte[] expectedInput = Random.randBytes(new java.util.Random().nextInt(300));
      byte[] key = Random.randBytes(32);
      DjbCipher cipher = createInstance(key);
      byte[] output = cipher.encrypt(expectedInput);
      byte[] nonce = Arrays.copyOf(output, cipher.nonceSizeInBytes());
      byte[] actualInput = cipher.decrypt(output);
      assertTrue(
          String.format(
              "\n\nMessage: %s\nKey: %s\nNonce: %s\nOutput: %s\nDecrypted Msg: %s\n",
              TestUtil.hexEncode(expectedInput),
              TestUtil.hexEncode(key),
              TestUtil.hexEncode(nonce),
              TestUtil.hexEncode(output),
              TestUtil.hexEncode(actualInput)),
          Arrays.equals(expectedInput, actualInput));
    }
  }

  @Test
  public void testNewCipherThrowsIllegalArgExpWhenKeyLenIsLessThan32() {
    try {
      createInstance(new byte[1]);
      fail("Expected IllegalArgumentException.");
    } catch (IllegalArgumentException e) {
      assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
    }
  }

  @Test
  public void testNewCipherThrowsIllegalArgExpWhenKeyLenIsGreaterThan32() {
    try {
      createInstance(new byte[33]);
      fail("Expected IllegalArgumentException.");
    } catch (IllegalArgumentException e) {
      assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
    }
  }

  @Test
  public void testDecryptThrowsGeneralSecurityExpWhenCiphertextIsTooShort() {
    DjbCipher cipher = createInstance(new byte[32]);
    try {
      cipher.decrypt(new byte[2]);
      fail("Expected GeneralSecurityException.");
    } catch (GeneralSecurityException e) {
      assertThat(e).hasMessageThat().containsMatch("ciphertext too short");
    }
  }
}
