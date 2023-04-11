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
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HashSet;
import javax.crypto.AEADBadTagException;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for AesEax. */
@RunWith(JUnit4.class)
public class AesEaxJceTest {
  private static final int KEY_SIZE = 16;
  private static final int IV_SIZE = 16;
  private Integer[] keySizeInBytes;
  private Integer[] ivSizeInBytes;

  @Before
  public void setUp() throws Exception {

    keySizeInBytes = new Integer[] {16, 32};
    ivSizeInBytes = new Integer[] {12, 16};
  }

  @Test
  public void testWycheproofVectors() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    JsonObject json =
        WycheproofTestUtil.readJson("../wycheproof/testvectors/aes_eax_test.json");
    int errors = 0;
    int cntSkippedTests = 0;
    JsonArray testGroups = json.getAsJsonArray("testGroups");
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      int keySize = group.get("keySize").getAsInt();
      int ivSize = group.get("ivSize").getAsInt();
      JsonArray tests = group.getAsJsonArray("tests");
      if (!Arrays.asList(keySizeInBytes).contains(keySize / 8)
          || !Arrays.asList(ivSizeInBytes).contains(ivSize / 8)) {
        cntSkippedTests += tests.size();
        continue;
      }
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
        String result = testcase.get("result").getAsString();
        try {
          AesEaxJce eax = new AesEaxJce(key, iv.length);
          byte[] decrypted = eax.decrypt(ciphertext, aad);
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
    System.out.printf("Number of tests skipped: %d", cntSkippedTests);
    assertEquals(0, errors);
  }

  @Test
  public void testEncryptDecrypt() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] aad = new byte[] {1, 2, 3};
    byte[] key = Random.randBytes(KEY_SIZE);
    AesEaxJce eax = new AesEaxJce(key, IV_SIZE);
    for (int messageSize = 0; messageSize < 75; messageSize++) {
      byte[] message = Random.randBytes(messageSize);
      byte[] ciphertext = eax.encrypt(message, aad);
      byte[] decrypted = eax.decrypt(ciphertext, aad);
      assertArrayEquals(message, decrypted);
    }
  }

  @Test
  public void testModifyCiphertext() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testModifyCiphertext(16, 16);
    testModifyCiphertext(16, 12);
    testModifyCiphertext(24, 16);
    testModifyCiphertext(32, 16);
  }

  public void testModifyCiphertext(int keySizeInBytes, int ivSizeInBytes) throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] aad = new byte[] {1, 2, 3};
    // TODO(tholenst): Investigate why this fails for "keySizeInBytes" instead of "KEY_SIZE".
    byte[] key = Random.randBytes(KEY_SIZE);
    byte[] message = Random.randBytes(32);
    AesEaxJce eax = new AesEaxJce(key, ivSizeInBytes);
    byte[] ciphertext = eax.encrypt(message, aad);

    // Flipping bits
    for (int b = 0; b < ciphertext.length; b++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modified = Arrays.copyOf(ciphertext, ciphertext.length);
        modified[b] ^= (byte) (1 << bit);
        try {
          byte[] unused = eax.decrypt(modified, aad);
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
        byte[] unused = eax.decrypt(modified, aad);
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
          byte[] unused = eax.decrypt(ciphertext, modified);
          fail("Decrypting with modified aad should fail");
        } catch (AEADBadTagException ex) {
          // This is expected.
        }
      }
    }
  }

  @Test
  public void testNullPlaintextOrCiphertext() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    AesEaxJce eax = new AesEaxJce(Random.randBytes(KEY_SIZE), IV_SIZE);
    byte[] aad = new byte[] {1, 2, 3};
    assertThrows(
        NullPointerException.class,
        () -> {
          byte[] unused = eax.encrypt(null, aad);
        });
    assertThrows(
        NullPointerException.class,
        () -> {
          byte[] unused = eax.encrypt(null, null);
        });
    assertThrows(
        NullPointerException.class,
        () -> {
          byte[] unused = eax.decrypt(null, aad);
        });
    assertThrows(
        NullPointerException.class,
        () -> {
          byte[] unused = eax.decrypt(null, null);
        });
  }

  @Test
  public void testEmptyAssociatedData() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] aad = new byte[0];
    byte[] key = Random.randBytes(KEY_SIZE);
    AesEaxJce eax = new AesEaxJce(key, IV_SIZE);
    for (int messageSize = 0; messageSize < 75; messageSize++) {
      byte[] message = Random.randBytes(messageSize);
      { // encrypting with aad as a 0-length array
        byte[] ciphertext = eax.encrypt(message, aad);
        byte[] decrypted = eax.decrypt(ciphertext, aad);
        assertArrayEquals(message, decrypted);
        byte[] decrypted2 = eax.decrypt(ciphertext, null);
        assertArrayEquals(message, decrypted2);
        byte[] badAad = new byte[] {1, 2, 3};
        assertThrows(
            AEADBadTagException.class,
            () -> {
              byte[] unused = eax.decrypt(ciphertext, badAad);
            });
      }
      { // encrypting with aad equal to null
        byte[] ciphertext = eax.encrypt(message, null);
        byte[] decrypted = eax.decrypt(ciphertext, aad);
        assertArrayEquals(message, decrypted);
        byte[] decrypted2 = eax.decrypt(ciphertext, null);
        assertArrayEquals(message, decrypted2);
        byte[] badAad = new byte[] {1, 2, 3};
        assertThrows(
            AEADBadTagException.class,
            () -> {
              byte[] unused = eax.decrypt(ciphertext, badAad);
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

    final int samples = 1 << 17;
    byte[] key = Random.randBytes(KEY_SIZE);
    byte[] message = new byte[0];
    byte[] aad = Random.randBytes(20);
    AesEaxJce eax = new AesEaxJce(key, IV_SIZE);
    HashSet<String> ciphertexts = new HashSet<>();
    for (int i = 0; i < samples; i++) {
      byte[] ct = eax.encrypt(message, aad);
      String ctHex = Hex.encode(ct);
      assertThat(ciphertexts).doesNotContain(ctHex);
      ciphertexts.add(ctHex);
    }
  }

  @Test
  public void testEncryptDecryptLongMessage() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] key = Random.randBytes(KEY_SIZE);
    AesEaxJce eax = new AesEaxJce(key, IV_SIZE);

    byte[] message = Random.randBytes(150000);
    byte[] aad = Random.randBytes(20);

    byte[] ciphertext = eax.encrypt(message, aad);
    byte[] decrypted = eax.decrypt(ciphertext, aad);
    assertArrayEquals(message, decrypted);
  }

  @Test
  public void testFailIfFipsModeUsed() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());

    byte[] key = Random.randBytes(16);
    assertThrows(GeneralSecurityException.class, () -> new AesEaxJce(key, IV_SIZE));
  }
}
