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
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.TestUtil;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.HashSet;
import javax.crypto.AEADBadTagException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for XChaCha20Poly1305. */
@RunWith(JUnit4.class)
public class XChaCha20Poly1305Test {
  private static final Charset UTF_8 = Charset.forName("UTF-8");
  private static final int KEY_SIZE = 32;

  // From libsodium's test/default/aead_xchacha20poly1305.c
  // see test/default/aead_xchacha20poly1305.exp for ciphertext values.
  private static final byte[] KEY =
      TestUtil.hexDecode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
  private static final String NONCE = "07000000404142434445464748494a4b0000000000000000";
  private static final byte[] AD = TestUtil.hexDecode("50515253c0c1c2c3c4c5c6c7");

  public Aead createInstance(byte[] key) throws InvalidKeyException {
    return new XChaCha20Poly1305(key);
  }

  @Test
  public void testWithLibSodiumTestVector() throws GeneralSecurityException {
    String in =
        TestUtil.hexEncode(
            ("Ladies and Gentlemen of the class of '99: If I could offer you only one "
                    + "tip for the future, sunscreen would be it.")
                .getBytes(UTF_8));
    Aead cipher = new XChaCha20Poly1305(KEY);
    byte[] c =
        TestUtil.hexDecode(
            NONCE
                + "453c0693a7407f04ff4c56aedb17a3c0a1afff01174930fc22287c33dbcf0ac8"
                + "b89ad929530a1bb3ab5e69f24c7f6070c8f840c9abb4f69fbfc8a7ff5126faee"
                + "bbb55805ee9c1cf2ce5a57263287aec5780f04ec324c3514122cfc3231fc1a8b"
                + "718a62863730a2702bb76366116bed09e0fd"
                + "5c6d84b6b0c1abaf249d5dd0f7f5a7ea"); // tag
    assertThat(TestUtil.hexEncode(cipher.decrypt(c, AD))).isEqualTo(in);
  }

  @Test
  public void testEmptyAdWithLibSodiumTestVector() throws GeneralSecurityException {
    String in =
        TestUtil.hexEncode(
            ("Ladies and Gentlemen of the class of '99: If I could offer you only one "
                    + "tip for the future, sunscreen would be it.")
                .getBytes(UTF_8));
    Aead cipher = new XChaCha20Poly1305(KEY);
    byte[] c =
        TestUtil.hexDecode(
            NONCE
                + "453c0693a7407f04ff4c56aedb17a3c0a1afff01174930fc22287c33dbcf0ac8"
                + "b89ad929530a1bb3ab5e69f24c7f6070c8f840c9abb4f69fbfc8a7ff5126faee"
                + "bbb55805ee9c1cf2ce5a57263287aec5780f04ec324c3514122cfc3231fc1a8b"
                + "718a62863730a2702bb76366116bed09e0fd"
                + "d4c860b7074be894fac9697399be5cc1"); // tag
    assertThat(TestUtil.hexEncode(cipher.decrypt(c, new byte[0]))).isEqualTo(in);
  }

  @Test
  public void testSnufflePoly1305ThrowsIllegalArgExpWhenKeyLenIsGreaterThan32()
      throws InvalidKeyException {
    try {
      createInstance(new byte[KEY_SIZE + 1]);
      fail("Expected InvalidKeyException.");
    } catch (InvalidKeyException e) {
      assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
    }
  }

  @Test
  public void testSnufflePoly1305ThrowsIllegalArgExpWhenKeyLenIsLessThan32()
      throws InvalidKeyException {
    try {
      createInstance(new byte[KEY_SIZE - 1]);
      fail("Expected InvalidKeyException.");
    } catch (InvalidKeyException e) {
      assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
    }
  }

  @Test
  public void testDecryptThrowsGeneralSecurityExpWhenCiphertextIsTooShort()
      throws InvalidKeyException {
    Aead cipher = createInstance(new byte[KEY_SIZE]);
    try {
      cipher.decrypt(new byte[27], new byte[1]);
      fail("Expected GeneralSecurityException.");
    } catch (GeneralSecurityException e) {
      assertThat(e).hasMessageThat().containsMatch("ciphertext too short");
    }
  }

  @Test
  public void testEncryptDecrypt() throws Exception {
    Aead aead = createInstance(Random.randBytes(KEY_SIZE));
    for (int i = 0; i < 100; i++) {
      byte[] message = Random.randBytes(i);
      byte[] aad = Random.randBytes(i);
      byte[] ciphertext = aead.encrypt(message, aad);
      byte[] decrypted = aead.decrypt(ciphertext, aad);
      assertArrayEquals(message, decrypted);
    }
  }

  @Test
  /** BC had a bug, where GCM failed for messages of size > 8192 */
  public void testLongMessages() throws Exception {
    if (TestUtil.isAndroid()) {
      System.out.println("testLongMessages doesn't work on Android, skipping");
      return;
    }
    int dataSize = 16;
    while (dataSize <= (1 << 24)) {
      byte[] plaintext = Random.randBytes(dataSize);
      byte[] aad = Random.randBytes(dataSize / 3);
      byte[] key = Random.randBytes(KEY_SIZE);
      Aead aead = createInstance(key);
      byte[] ciphertext = aead.encrypt(plaintext, aad);
      byte[] decrypted = aead.decrypt(ciphertext, aad);
      assertArrayEquals(plaintext, decrypted);
      dataSize += 5 * dataSize / 11;
    }
  }

  @Test
  public void testModifyCiphertext() throws Exception {
    byte[] key = Random.randBytes(KEY_SIZE);
    Aead aead = createInstance(key);
    byte[] aad = Random.randBytes(16);
    byte[] message = Random.randBytes(32);
    byte[] ciphertext = aead.encrypt(message, aad);

    // Flipping bits
    for (int b = 0; b < ciphertext.length; b++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modified = Arrays.copyOf(ciphertext, ciphertext.length);
        modified[b] ^= (byte) (1 << bit);
        try {
          byte[] unused = aead.decrypt(modified, aad);
          fail("Decrypting modified ciphertext should fail");
        } catch (AEADBadTagException ex) {
          // This is expected.
        }
      }
    }

    // Truncate the message.
    for (int length = 0; length < ciphertext.length; length++) {
      byte[] modified = Arrays.copyOf(ciphertext, length);
      try {
        byte[] unused = aead.decrypt(modified, aad);
        fail("Decrypting modified ciphertext should fail");
      } catch (GeneralSecurityException ex) {
        // This is expected.
        // This could be a AeadBadTagException when the tag verification
        // fails or some not yet specified Exception when the ciphertext is too short.
        // In all cases a GeneralSecurityException or a subclass of it must be thrown.
      }
    }

    // Modify AAD
    for (int b = 0; b < aad.length; b++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modified = Arrays.copyOf(aad, aad.length);
        modified[b] ^= (byte) (1 << bit);
        try {
          byte[] unused = aead.decrypt(ciphertext, modified);
          fail("Decrypting with modified aad should fail");
        } catch (AEADBadTagException ex) {
          // This is expected.
        }
      }
    }
  }

  /**
   * This is a very simple test for the randomness of the nonce. The test simply checks that the
   * multiple ciphertexts of the same message are distinct.
   */
  @Test
  public void testRandomNonce() throws Exception {
    byte[] key = Random.randBytes(KEY_SIZE);
    Aead aead = createInstance(key);
    byte[] message = new byte[0];
    byte[] aad = new byte[0];
    HashSet<String> ciphertexts = new HashSet<String>();
    final int samples = 1 << 17;
    for (int i = 0; i < samples; i++) {
      byte[] ct = aead.encrypt(message, aad);
      String ctHex = TestUtil.hexEncode(ct);
      assertFalse(ciphertexts.contains(ctHex));
      ciphertexts.add(ctHex);
    }
    assertEquals(samples, ciphertexts.size());
  }
}
