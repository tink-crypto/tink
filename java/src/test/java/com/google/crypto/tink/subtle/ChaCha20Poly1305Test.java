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
import com.google.crypto.tink.TestUtil.BytesMutation;
import com.google.crypto.tink.WycheproofTestUtil;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.HashSet;
import javax.crypto.AEADBadTagException;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for ChaCha20Poly1305. */
@RunWith(JUnit4.class)
public class ChaCha20Poly1305Test {
  private static final int KEY_SIZE = 32;

  public Aead createInstance(final byte[] key) throws InvalidKeyException {
    return new ChaCha20Poly1305(key);
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

    for (BytesMutation mutation : TestUtil.generateMutations(ciphertext)) {
      try {
        byte[] unused = aead.decrypt(mutation.value, aad);
        fail(
            String.format(
                "Decrypting modified ciphertext should fail : ciphertext = %s, aad = %s,"
                    + " description = %s",
                Hex.encode(mutation.value), aad, mutation.description));
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

  @Test
  public void testNullPlaintextOrCiphertext() throws Exception {
    Aead aead = createInstance(Random.randBytes(KEY_SIZE));
    try {
      byte[] aad = new byte[] {1, 2, 3};
      byte[] unused = aead.encrypt(null, aad);
      fail("Encrypting a null plaintext should fail");
    } catch (NullPointerException ex) {
      // This is expected.
    }
    try {
      byte[] unused = aead.encrypt(null, null);
      fail("Encrypting a null plaintext should fail");
    } catch (NullPointerException ex) {
      // This is expected.
    }
    try {
      byte[] aad = new byte[] {1, 2, 3};
      byte[] unused = aead.decrypt(null, aad);
      fail("Decrypting a null ciphertext should fail");
    } catch (NullPointerException ex) {
      // This is expected.
    }
    try {
      byte[] unused = aead.decrypt(null, null);
      fail("Decrypting a null ciphertext should fail");
    } catch (NullPointerException ex) {
      // This is expected.
    }
  }

  @Test
  public void testEmptyAssociatedData() throws Exception {
    byte[] aad = new byte[0];
    Aead aead = createInstance(Random.randBytes(KEY_SIZE));
    for (int messageSize = 0; messageSize < 75; messageSize++) {
      byte[] message = Random.randBytes(messageSize);
      {  // encrypting with aad as a 0-length array
        byte[] ciphertext = aead.encrypt(message, aad);
        byte[] decrypted = aead.decrypt(ciphertext, aad);
        assertArrayEquals(message, decrypted);
        byte[] decrypted2 = aead.decrypt(ciphertext, null);
        assertArrayEquals(message, decrypted2);
        try {
          byte[] badAad = new byte[] {1, 2, 3};
          byte[] unused = aead.decrypt(ciphertext, badAad);
          fail("Decrypting with modified aad should fail");
        } catch (AEADBadTagException ex) {
          // This is expected.
        }
      }
      {  // encrypting with aad equal to null
        byte[] ciphertext = aead.encrypt(message, null);
        byte[] decrypted = aead.decrypt(ciphertext, aad);
        assertArrayEquals(message, decrypted);
        byte[] decrypted2 = aead.decrypt(ciphertext, null);
        assertArrayEquals(message, decrypted2);
        try {
          byte[] badAad = new byte[] {1, 2, 3};
          byte[] unused = aead.decrypt(ciphertext, badAad);
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
    final int samples = 1 << 10;
    for (int i = 0; i < samples; i++) {
      byte[] ct = aead.encrypt(message, aad);
      String ctHex = TestUtil.hexEncode(ct);
      assertFalse(ciphertexts.contains(ctHex));
      ciphertexts.add(ctHex);
    }
    assertEquals(samples, ciphertexts.size());
  }

  @Test
  public void testWycheproofVectors() throws Exception {
    JSONObject json =
        WycheproofTestUtil.readJson(
            "../wycheproof/testvectors/chacha20_poly1305_test.json");
    int errors = 0;
    JSONArray testGroups = json.getJSONArray("testGroups");
    for (int i = 0; i < testGroups.length(); i++) {
      JSONObject group = testGroups.getJSONObject(i);
      JSONArray tests = group.getJSONArray("tests");
      for (int j = 0; j < tests.length(); j++) {
        JSONObject testcase = tests.getJSONObject(j);
        String tcId =
            String.format(
                "testcase %d (%s)", testcase.getInt("tcId"), testcase.getString("comment"));
        byte[] iv = Hex.decode(testcase.getString("iv"));
        byte[] key = Hex.decode(testcase.getString("key"));
        byte[] msg = Hex.decode(testcase.getString("msg"));
        byte[] aad = Hex.decode(testcase.getString("aad"));
        byte[] ct = Hex.decode(testcase.getString("ct"));
        byte[] tag = Hex.decode(testcase.getString("tag"));
        byte[] ciphertext = Bytes.concat(iv, ct, tag);
        // Result is one of "valid", "invalid", "acceptable".
        // "valid" are test vectors with matching plaintext, ciphertext and tag.
        // "invalid" are test vectors with invalid parameters or invalid ciphertext and tag.
        // "acceptable" are test vectors with weak parameters or legacy formats.
        String result = testcase.getString("result");
        try {
          Aead aead = createInstance(key);
          byte[] decrypted = aead.decrypt(ciphertext, aad);
          boolean eq = TestUtil.arrayEquals(decrypted, msg);
          if (result.equals("invalid")) {
            System.out.printf(
                "FAIL %s: accepting invalid ciphertext, cleartext: %s, decrypted: %s%n",
                tcId, Hex.encode(msg), Hex.encode(decrypted));
            errors++;
          } else {
            if (!eq) {
              System.out.printf(
                  "FAIL %s: incorrect decryption, result: %s, expected: %s%n",
                  tcId, Hex.encode(decrypted), Hex.encode(msg));
              errors++;
            }
          }
        } catch (GeneralSecurityException ex) {
          if (result.equals("valid")) {
            System.out.printf("FAIL %s: cannot decrypt, exception %s%n", tcId, ex);
            errors++;
          }
        }
      }
    }
    assertEquals(0, errors);
  }
}
