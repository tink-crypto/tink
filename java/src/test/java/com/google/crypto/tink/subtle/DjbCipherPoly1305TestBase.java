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

import static com.google.crypto.tink.subtle.DjbCipher.KEY_SIZE_IN_BYTES;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.common.truth.Truth;
import com.google.crypto.tink.TestUtil;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.Test;

/**
 * Unit test base class for DjbCipherPoly1305.
 */
public abstract class DjbCipherPoly1305TestBase {

  protected abstract DjbCipherPoly1305 createInstance(byte[] key);

  @Test
  public void testRandomChaCha20Poly1305() throws GeneralSecurityException {
    for (int i = 0; i < 1000; i++) {
      byte[] expectedInput = Random.randBytes(new java.util.Random().nextInt(300));
      byte[] aad = Random.randBytes(DjbCipherPoly1305.MAC_TAG_SIZE_IN_BYTES);
      byte[] key = Random.randBytes(KEY_SIZE_IN_BYTES);
      DjbCipherPoly1305 cipher = createInstance(key);
      byte[] output = cipher.encrypt(expectedInput, aad);
      byte[] nonce = Arrays.copyOfRange(
          output, DjbCipherPoly1305.MAC_TAG_SIZE_IN_BYTES,
          cipher.nonceSizeInBytes() + DjbCipherPoly1305.MAC_TAG_SIZE_IN_BYTES);
      byte[] actualInput = null;
      try {
        actualInput = cipher.decrypt(output, aad);
        assertTrue(Arrays.equals(expectedInput, actualInput));
      } catch (Throwable e) {
        String error = String.format(
            "\n\nIteration: %d\nMessage: %s\nAad: %s\nKey: %s\nNonce: %s\nOutput: %s\n"
                + "Decrypted Msg: %s\n",
            i,
            TestUtil.hexEncode(expectedInput),
            TestUtil.hexEncode(aad),
            TestUtil.hexEncode(key),
            TestUtil.hexEncode(nonce),
            TestUtil.hexEncode(output),
            actualInput == null ? "null" : TestUtil.hexEncode(actualInput));
        fail(error);
      }
    }
  }

  @Test
  public void testEncryptingEmptyString() throws GeneralSecurityException {
    byte[] aad = Random.randBytes(DjbCipherPoly1305.MAC_TAG_SIZE_IN_BYTES);
    byte[] key = Random.randBytes(KEY_SIZE_IN_BYTES);
    DjbCipherPoly1305 cipher = createInstance(key);
    byte[] ciphertext = cipher.encrypt(new byte[0], aad);
    Truth.assertThat(cipher.decrypt(ciphertext, aad)).isEqualTo(new byte[0]);
  }

  @Test
  public void testDjbCipherPoly1305ThrowsIllegalArgExpWhenKeyLenIsGreaterThan32() {
    try {
      createInstance(new byte[KEY_SIZE_IN_BYTES + 1]);
      fail("Expected IllegalArgumentException.");
    } catch (IllegalArgumentException e) {
      Truth.assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
    }
  }

  @Test
  public void testDjbCipherPoly1305ThrowsIllegalArgExpWhenKeyLenIsLessThan32() {
    try {
      createInstance(new byte[KEY_SIZE_IN_BYTES - 1]);
      fail("Expected IllegalArgumentException.");
    } catch (IllegalArgumentException e) {
      Truth.assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
    }
  }

  @Test
  public void testDjbCipherDecryptThrowsGeneralSecurityExpWhenCiphertextIsTooShort() {
    DjbCipherPoly1305 cipher = createInstance(new byte[KEY_SIZE_IN_BYTES]);
    try {
      cipher.decrypt(new byte[27], new byte[1]);
      fail("Expected GeneralSecurityException.");
    } catch (GeneralSecurityException e) {
      Truth.assertThat(e).hasMessageThat().containsMatch("ciphertext too short");
    }
  }
}
