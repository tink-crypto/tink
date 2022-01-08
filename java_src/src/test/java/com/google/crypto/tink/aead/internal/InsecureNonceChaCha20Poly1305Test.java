// Copyright 2021 Google LLC
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

package com.google.crypto.tink.aead.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.testing.TestUtil.BytesMutation;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.HashSet;
import javax.crypto.AEADBadTagException;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link InsecureNonceChaCha20Poly1305}. */
@RunWith(JUnit4.class)
public class InsecureNonceChaCha20Poly1305Test {
  private static final int KEY_SIZE_IN_BYTES = 32;
  private static final int NONCE_SIZE_IN_BYTES = 12;
  private static final int TAG_SIZE_IN_BYTES = 16;

  public InsecureNonceChaCha20Poly1305 createInstance(final byte[] key)
      throws GeneralSecurityException {
    return new InsecureNonceChaCha20Poly1305(key);
  }

  @Test
  public void testSnufflePoly1305ThrowsInvalidAlgorithmParameterExpWhenKeyLenIsGreaterThan32()
      throws InvalidKeyException {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    InvalidKeyException e =
        assertThrows(
            InvalidKeyException.class,
            () -> createInstance(new byte[KEY_SIZE_IN_BYTES + 1]));
    assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
  }

  @Test
  public void testSnufflePoly1305ThrowsInvalidAlgorithmParameterExpWhenKeyLenIsLessThan32()
      throws InvalidKeyException {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    InvalidKeyException e =
        assertThrows(
            InvalidKeyException.class, () -> createInstance(new byte[KEY_SIZE_IN_BYTES - 1]));
    assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
  }

  @Test
  public void testDecryptThrowsGeneralSecurityExpWhenCiphertextIsTooShort()
      throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    InsecureNonceChaCha20Poly1305 cipher =
        createInstance(new byte[KEY_SIZE_IN_BYTES]);
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () ->
                cipher.decrypt(
                    new byte[NONCE_SIZE_IN_BYTES], new byte[TAG_SIZE_IN_BYTES - 1], new byte[1]));
    assertThat(e).hasMessageThat().containsMatch("ciphertext too short");
  }

  @Test
  public void testEncryptDecrypt() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    InsecureNonceChaCha20Poly1305 cipher =
        createInstance(Random.randBytes(KEY_SIZE_IN_BYTES));
    for (int i = 0; i < 100; i++) {
      byte[] nonce = Random.randBytes(NONCE_SIZE_IN_BYTES);
      byte[] message = Random.randBytes(i);
      byte[] aad = Random.randBytes(i);
      byte[] ciphertext = cipher.encrypt(nonce, message, aad);
      byte[] decrypted = cipher.decrypt(nonce, ciphertext, aad);
      assertArrayEquals(message, decrypted);
    }
  }

  /** BC had a bug, where GCM failed for messages of size > 8192 */
  @Test
  public void testLongMessages() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());
    Assume.assumeFalse(TestUtil.isAndroid()); // Doesn't work on Android

    int dataSize = 16;
    while (dataSize <= (1 << 24)) {
      byte[] plaintext = Random.randBytes(dataSize);
      byte[] aad = Random.randBytes(dataSize / 3);
      byte[] key = Random.randBytes(KEY_SIZE_IN_BYTES);
      byte[] nonce = Random.randBytes(NONCE_SIZE_IN_BYTES);
      InsecureNonceChaCha20Poly1305 cipher = createInstance(key);
      byte[] ciphertext = cipher.encrypt(nonce, plaintext, aad);
      byte[] decrypted = cipher.decrypt(nonce, ciphertext, aad);
      assertArrayEquals(plaintext, decrypted);
      dataSize += 5 * dataSize / 11;
    }
  }

  @Test
  public void testModifyCiphertext() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] key = Random.randBytes(KEY_SIZE_IN_BYTES);
    InsecureNonceChaCha20Poly1305 cipher = createInstance(key);
    byte[] aad = Random.randBytes(16);
    byte[] message = Random.randBytes(32);
    byte[] nonce = Random.randBytes(NONCE_SIZE_IN_BYTES);
    byte[] ciphertext = cipher.encrypt(nonce, message, aad);

    for (BytesMutation mutation : TestUtil.generateMutations(ciphertext)) {
      assertThrows(
          String.format(
              "Decrypting modified ciphertext should fail : ciphertext = %s, aad = %s,"
                  + " description = %s",
              Hex.encode(mutation.value), Arrays.toString(aad), mutation.description),
          GeneralSecurityException.class,
          () -> {
            byte[] unused = cipher.decrypt(nonce, mutation.value, aad);
          });
    }

    // Modify AAD
    for (int b = 0; b < aad.length; b++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modified = Arrays.copyOf(aad, aad.length);
        modified[b] ^= (byte) (1 << bit);
        assertThrows(
            AEADBadTagException.class,
            () -> {
              byte[] unused = cipher.decrypt(nonce, ciphertext, modified);
            });
      }
    }
  }

  @Test
  public void testNullPlaintextOrCiphertext() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    InsecureNonceChaCha20Poly1305 cipher =
        createInstance(Random.randBytes(KEY_SIZE_IN_BYTES));
    byte[] nonce = Random.randBytes(NONCE_SIZE_IN_BYTES);
    byte[] aad = new byte[] {1, 2, 3};
    assertThrows(
        NullPointerException.class,
        () -> {
          byte[] unused = cipher.encrypt(nonce, null, aad);
        });
    assertThrows(
        NullPointerException.class,
        () -> {
          byte[] unused = cipher.encrypt(nonce, null, null);
        });
    assertThrows(
        NullPointerException.class,
        () -> {
          byte[] unused = cipher.decrypt(nonce, null, aad);
        });
    assertThrows(
        NullPointerException.class,
        () -> {
          byte[] unused = cipher.decrypt(nonce, null, null);
        });
  }

  @Test
  public void testEmptyAssociatedData() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] aad = new byte[0];
    InsecureNonceChaCha20Poly1305 cipher =
        createInstance(Random.randBytes(KEY_SIZE_IN_BYTES));
    byte[] nonce = Random.randBytes(NONCE_SIZE_IN_BYTES);
    for (int messageSize = 0; messageSize < 75; messageSize++) {
      byte[] message = Random.randBytes(messageSize);
      { // encrypting with aad as a 0-length array
        byte[] ciphertext = cipher.encrypt(nonce, message, aad);
        byte[] decrypted = cipher.decrypt(nonce, ciphertext, aad);
        assertArrayEquals(message, decrypted);
        byte[] decrypted2 = cipher.decrypt(nonce, ciphertext, null);
        assertArrayEquals(message, decrypted2);
        byte[] badAad = new byte[] {1, 2, 3};
        assertThrows(
            AEADBadTagException.class,
            () -> {
              byte[] unused = cipher.decrypt(nonce, ciphertext, badAad);
            });
      }
      { // encrypting with aad equal to null
        byte[] ciphertext = cipher.encrypt(nonce, message, null);
        byte[] decrypted = cipher.decrypt(nonce, ciphertext, aad);
        assertArrayEquals(message, decrypted);
        byte[] decrypted2 = cipher.decrypt(nonce, ciphertext, null);
        assertArrayEquals(message, decrypted2);
        byte[] badAad = new byte[] {1, 2, 3};
        assertThrows(
            AEADBadTagException.class,
            () -> {
              byte[] unused = cipher.decrypt(nonce, ciphertext, badAad);
            });
      }
    }
  }

  /**
   * This test simply checks that multiple ciphertexts of the same message with a different nonce
   * are distinct.
   */
  @Test
  public void testNonce() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] key = Random.randBytes(KEY_SIZE_IN_BYTES);
    InsecureNonceChaCha20Poly1305 cipher = createInstance(key);
    byte[] message = new byte[0];
    byte[] aad = new byte[0];
    HashSet<String> ciphertexts = new HashSet<>();
    final int samples = 1 << 10;
    for (int i = 0; i < samples; i++) {
      byte[] nonce = Random.randBytes(NONCE_SIZE_IN_BYTES);
      byte[] ct = cipher.encrypt(nonce, message, aad);
      String ctHex = TestUtil.hexEncode(ct);
      assertThat(ciphertexts).doesNotContain(ctHex);
      ciphertexts.add(ctHex);
    }
    assertThat(ciphertexts).hasSize(samples);
  }

  @Test
  public void testWycheproofVectors() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    JsonObject json =
        WycheproofTestUtil.readJson(
            "../wycheproof/testvectors/chacha20_poly1305_test.json");
    int errors = 0;
    JsonArray testGroups = json.getAsJsonArray("testGroups");
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      JsonArray tests = group.getAsJsonArray("tests");
      for (int j = 0; j < tests.size(); j++) {
        JsonObject testcase = tests.get(j).getAsJsonObject();
        String tcId =
            String.format(
                "testcase %d (%s)",
                testcase.get("tcId").getAsInt(), testcase.get("comment").getAsString());
        byte[] iv = Hex.decode(testcase.get("iv").getAsString());
        byte[] key = Hex.decode(testcase.get("key").getAsString());
        byte[] msg = Hex.decode(testcase.get("msg").getAsString());
        byte[] aad = Hex.decode(testcase.get("aad").getAsString());
        byte[] ct = Hex.decode(testcase.get("ct").getAsString());
        byte[] tag = Hex.decode(testcase.get("tag").getAsString());
        byte[] ciphertext = Bytes.concat(ct, tag);
        // Result is one of "valid", "invalid", "acceptable".
        // "valid" are test vectors with matching plaintext, ciphertext and tag.
        // "invalid" are test vectors with invalid parameters or invalid ciphertext and tag.
        // "acceptable" are test vectors with weak parameters or legacy formats.
        String result = testcase.get("result").getAsString();
        try {
          InsecureNonceChaCha20Poly1305 cipher = createInstance(key);
          // Encryption.
          byte[] encrypted = cipher.encrypt(iv, msg, aad);
          boolean ciphertextMatches = TestUtil.arrayEquals(encrypted, ciphertext);
          if (result.equals("valid") && !ciphertextMatches) {
            System.err.printf(
                "FAIL %s: incorrect encryption, result: %s, expected: %s%n",
                tcId, Hex.encode(encrypted), Hex.encode(ciphertext));
            errors++;
          }
          // Decryption.
          byte[] decrypted = cipher.decrypt(iv, ciphertext, aad);
          boolean plaintextMatches = TestUtil.arrayEquals(decrypted, msg);
          if (result.equals("invalid")) {
            System.out.printf(
                "FAIL %s: accepting invalid ciphertext, cleartext: %s, decrypted: %s%n",
                tcId, Hex.encode(msg), Hex.encode(decrypted));
            errors++;
          } else {
            if (!plaintextMatches) {
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

  @Test
  public void testFailIfFipsModuleNotAvailable() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());

    byte[] key = Random.randBytes(32);
    assertThrows(
        GeneralSecurityException.class,
        () -> new InsecureNonceChaCha20Poly1305(key));
  }
}
