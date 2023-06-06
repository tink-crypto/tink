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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.config.TinkFips;
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

/** Unit tests for ChaCha20Poly1305. */
@RunWith(JUnit4.class)
public class ChaCha20Poly1305Test {
  private static final int KEY_SIZE = 32;

  public Aead createInstance(final byte[] key) throws GeneralSecurityException {
    return new ChaCha20Poly1305(key);
  }

  @Test
  public void testSnufflePoly1305ThrowsIllegalArgExpWhenKeyLenIsGreaterThan32()
      throws InvalidKeyException {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    InvalidKeyException e =
        assertThrows(InvalidKeyException.class, () -> createInstance(new byte[KEY_SIZE + 1]));
    assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
  }

  @Test
  public void testSnufflePoly1305ThrowsIllegalArgExpWhenKeyLenIsLessThan32()
      throws InvalidKeyException {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    InvalidKeyException e =
        assertThrows(InvalidKeyException.class, () -> createInstance(new byte[KEY_SIZE - 1]));
    assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
  }

  @Test
  public void testDecryptThrowsGeneralSecurityExpWhenCiphertextIsTooShort()
      throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    Aead cipher = createInstance(new byte[KEY_SIZE]);
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> cipher.decrypt(new byte[27], new byte[1]));
    assertThat(e).hasMessageThat().containsMatch("ciphertext too short");
  }

  @Test
  public void testEncryptDecrypt() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

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
  /* BC had a bug, where GCM failed for messages of size > 8192 */
  public void testLongMessages() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());
    Assume.assumeFalse(TestUtil.isAndroid()); // Doesn't work on Android

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
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] key = Random.randBytes(KEY_SIZE);
    Aead aead = createInstance(key);
    byte[] aad = Random.randBytes(16);
    byte[] message = Random.randBytes(32);
    byte[] ciphertext = aead.encrypt(message, aad);

    for (BytesMutation mutation : TestUtil.generateMutations(ciphertext)) {
      assertThrows(
          String.format(
              "Decrypting modified ciphertext should fail : ciphertext = %s, aad = %s,"
                  + " description = %s",
              Hex.encode(mutation.value), Arrays.toString(aad), mutation.description),
          GeneralSecurityException.class,
          () -> {
            byte[] unused = aead.decrypt(mutation.value, aad);
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
              byte[] unused = aead.decrypt(ciphertext, modified);
            });
      }
    }
  }

  @Test
  public void testNullPlaintextOrCiphertext() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    Aead aead = createInstance(Random.randBytes(KEY_SIZE));
    byte[] aad = new byte[] {1, 2, 3};
    assertThrows(
        NullPointerException.class,
        () -> {
          byte[] unused = aead.encrypt(null, aad);
        });
    assertThrows(
        NullPointerException.class,
        () -> {
          byte[] unused = aead.encrypt(null, null);
        });
    assertThrows(
        NullPointerException.class,
        () -> {
          byte[] unused = aead.decrypt(null, aad);
        });
    assertThrows(
        NullPointerException.class,
        () -> {
          byte[] unused = aead.decrypt(null, null);
        });
  }

  @Test
  public void testEmptyAssociatedData() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

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
        byte[] badAad = new byte[] {1, 2, 3};
        assertThrows(
            AEADBadTagException.class,
            () -> {
              byte[] unused = aead.decrypt(ciphertext, badAad);
            });
      }
      {  // encrypting with aad equal to null
        byte[] ciphertext = aead.encrypt(message, null);
        byte[] decrypted = aead.decrypt(ciphertext, aad);
        assertArrayEquals(message, decrypted);
        byte[] decrypted2 = aead.decrypt(ciphertext, null);
        assertArrayEquals(message, decrypted2);
        byte[] badAad = new byte[] {1, 2, 3};
        assertThrows(
            AEADBadTagException.class,
            () -> {
              byte[] unused = aead.decrypt(ciphertext, badAad);
            });
      }
    }
  }

  /**
   * This is a very simple test for the randomness of the nonce. The test simply checks that the
   * multiple ciphertexts of the same message are distinct.
   */
  @Test
  public void testRandomNonce() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] key = Random.randBytes(KEY_SIZE);
    Aead aead = createInstance(key);
    byte[] message = new byte[0];
    byte[] aad = new byte[0];
    HashSet<String> ciphertexts = new HashSet<String>();
    final int samples = 1 << 10;
    for (int i = 0; i < samples; i++) {
      byte[] ct = aead.encrypt(message, aad);
      String ctHex = Hex.encode(ct);
      assertFalse(ciphertexts.contains(ctHex));
      ciphertexts.add(ctHex);
    }
    assertEquals(samples, ciphertexts.size());
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
        byte[] ciphertext = Bytes.concat(iv, ct, tag);
        // Result is one of "valid", "invalid", "acceptable".
        // "valid" are test vectors with matching plaintext, ciphertext and tag.
        // "invalid" are test vectors with invalid parameters or invalid ciphertext and tag.
        // "acceptable" are test vectors with weak parameters or legacy formats.
        String result = testcase.get("result").getAsString();
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

  @Test
  public void testFailIfFipsModuleNotAvailable() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());

    byte[] key = Random.randBytes(32);
    assertThrows(GeneralSecurityException.class, () -> new ChaCha20Poly1305(key));
  }
}
