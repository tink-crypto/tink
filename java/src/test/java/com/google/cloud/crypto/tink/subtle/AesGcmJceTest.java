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

package com.google.cloud.crypto.tink.subtle;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.fail;
import static org.junit.Assert.assertTrue;

import com.google.cloud.crypto.tink.subtle.Random;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for AesGcm
 * TODO(bleichen): Add more tests.
 *   - test vectors for compatibility.
 *   - maybe add NIST style verification.
 *   - more tests for asynchronous encryption.
 *   - tests with long ciphertexts (e.g. BC had a bug with messages of size 8k or longer)
 *   - check that IVs are distinct.
 *   - more sizes for the AAD
 *   - modify the AAD.
 */
@RunWith(JUnit4.class)
public class AesGcmJceTest {

  @Test
  public void testEncryptDecrypt() throws Exception {
    final int KEY_SIZE = 16;
    byte aad[] = new byte[] {1, 2, 3};
    byte key[] = Random.randBytes(KEY_SIZE);
    AesGcmJce gcm = new AesGcmJce(key);
    for (int messageSize = 0; messageSize < 75; messageSize++) {
      byte[] message = Random.randBytes(messageSize);
      byte[] ciphertext = gcm.encrypt(message, aad);
      byte[] decrypted = gcm.decrypt(ciphertext, aad);
      assertArrayEquals(message, decrypted);
    }
  }

  @Test
  public void testModifyCiphertext() throws Exception {
    final int KEY_SIZE = 16;
    byte aad[] = new byte[] {1, 2, 3};
    byte key[] = Random.randBytes(KEY_SIZE);
    byte message[] = Random.randBytes(32);
    AesGcmJce gcm = new AesGcmJce(key);
    byte[] ciphertext = gcm.encrypt(message, aad);

    // Flipping bits
    for (int b = 0; b < ciphertext.length; b++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modified = Arrays.copyOf(ciphertext, ciphertext.length);
        modified[b] ^= (byte)(1 << bit);
        try {
          byte[] unused = gcm.decrypt(modified, aad);
          fail("Decrypting modified ciphertext should fail");
        } catch (GeneralSecurityException ex) {
          // This is expected.
          // AeadBadTagException is the typical case here,
          // but we only guarantee GeneralSecurityException for modified
          // ciphertexts in an AEAD.
        }
      }
    }

    // Truncate the message.
    for (int length = 0; length < ciphertext.length; length++) {
      byte[] modified = Arrays.copyOf(ciphertext, length);
      try {
        byte[] unused = gcm.decrypt(modified, aad);
        fail("Decrypting modified ciphertext should fail");
      } catch (GeneralSecurityException ex) {
        // This is expected.
        // This could be a AeadBadTagException when the tag verification
        // fails or some not yet specified Exception when the ciphertext is too short.
        // In all cases a GeneralSecurityException or a subclass of it must be thrown.
      }
    }
  }

  @Test
  /**
   * A very basic test for asynchronous encryption.
   */
  public void testAsync() throws Exception {
    final int KEY_SIZE = 16;
    byte aad[] = new byte[] {1, 2, 3};
    byte key[] = Random.randBytes(KEY_SIZE);
    AesGcmJce gcm = new AesGcmJce(key);
    byte[] plaintext = Random.randBytes(20);

    byte[] ciphertext = gcm.asyncEncrypt(plaintext, aad).get();
    byte[] decrypted = gcm.asyncDecrypt(ciphertext, aad).get();
    assertArrayEquals(plaintext, decrypted);
    for (int length = 0; length < ciphertext.length; length++) {
      byte[] truncated = Arrays.copyOf(ciphertext, length);
      try {
        byte[] unused = gcm.asyncDecrypt(truncated, aad).get();
        fail("Decrypting a truncated ciphertext should fail");
      } catch (ExecutionException ex) {
        // The decryption should fail because the ciphertext has been truncated.
        assertTrue(ex.getCause() instanceof GeneralSecurityException);
      }
    }
  }
}
