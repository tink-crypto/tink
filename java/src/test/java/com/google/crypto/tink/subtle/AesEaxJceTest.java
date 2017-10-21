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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.WycheproofTestUtil;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for AesEax.
 *
 * <p>TODO: Add more tests:
 *
 * <ul>
 *   <li>- maybe add NIST style verification.
 *   <li>- tests with long ciphertexts (e.g. BC had a bug with messages of size 8k or longer)
 *   <li>- check that IVs are distinct.
 *   <li>- use Github Wycheproof test vectors once they're published (b/66825199).
 * </ul>
 */
@RunWith(JUnit4.class)
public class AesEaxJceTest {
  private static final int KEY_SIZE = 16;
  private static final int IV_SIZE = 16;
  private Integer[] keySizeInBytes;
  private Integer[] ivSizeInBytes;

  @Before
  public void setUp() throws Exception {
    if (Cipher.getMaxAllowedKeyLength("AES") < 256) {
      System.out.println(
          "Unlimited Strength Jurisdiction Policy Files are required"
              + " but not installed. Skip tests with keys larger than 128 bits.");
      keySizeInBytes = new Integer[] {16};
    } else {
      keySizeInBytes = new Integer[] {16, 24, 32};
    }
    ivSizeInBytes = new Integer[] {12, 16};
  }

  @Test
  public void testWycheproofVectors() throws Exception {
    if (TestUtil.isAndroid()) {
      System.out.println("testWycheproofVectors doesn't work on Android, skipping");
      return;
    }
    JSONObject json = TestUtil.readJson("testdata/wycheproof/aes_eax_test.json");
    WycheproofTestUtil.checkAlgAndVersion(json, "AES-EAX", "0.0a14");
    int numTests = json.getInt("numberOfTests");
    int cntTests = 0;
    int cntSkippedTests = 0;
    int errors = 0;
    JSONArray testGroups = json.getJSONArray("testGroups");
    for (int i = 0; i < testGroups.length(); i++) {
      JSONObject group = testGroups.getJSONObject(i);
      int keySize = group.getInt("keySize");
      int ivSize = group.getInt("ivSize");
      JSONArray tests = group.getJSONArray("tests");
      if (!Arrays.asList(keySizeInBytes).contains(keySize / 8)
          || !Arrays.asList(ivSizeInBytes).contains(ivSize / 8)) {
        cntSkippedTests += tests.length();
        continue;
      }
      for (int j = 0; j < tests.length(); j++) {
        cntTests++;
        JSONObject testcase = tests.getJSONObject(j);
        int tcid = testcase.getInt("tcId");
        String tc = "tcId: " + tcid + " " + testcase.getString("comment");
        byte[] iv = Hex.decode(testcase.getString("iv"));
        byte[] key = Hex.decode(testcase.getString("key"));
        byte[] msg = Hex.decode(testcase.getString("msg"));
        byte[] aad = Hex.decode(testcase.getString("aad"));
        byte[] ct = Hex.decode(testcase.getString("ct"));
        byte[] tag = Hex.decode(testcase.getString("tag"));
        byte[] ciphertext = Bytes.concat(iv, ct, tag);
        String result = testcase.getString("result");
        try {
          AesEaxJce eax = new AesEaxJce(key, iv.length);
          byte[] decrypted = eax.decrypt(ciphertext, aad);
          boolean eq = TestUtil.arrayEquals(decrypted, msg);
          if (result.equals("invalid")) {
            System.out.println("Decrypted invalid ciphertext " + tc + " eq:" + eq);
            errors++;
          } else {
            if (!eq) {
              System.out.println(
                  "Incorrect decryption " + tc + " decrypted:" + TestUtil.hexEncode(decrypted));
            }
          }
        } catch (GeneralSecurityException ex) {
          if (result.equals("valid")) {
            System.out.println("Failed to decrypt " + tc);
            errors++;
          }
        }
      }
    }
    assertEquals(0, errors);
    assertEquals(numTests, cntTests + cntSkippedTests);
  }

  @Test
  public void testEncryptDecrypt() throws Exception {
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
    testModifyCiphertext(16, 16);
    testModifyCiphertext(16, 12);
    // TODO(bleichen): Skipping test with key sizes larger than 128 bits because of
    //   https://buganizer.corp.google.com/issues/35928521
    // testModifyCiphertext(24, 16);
    // testModifyCiphertext(32, 16);
  }

  public void testModifyCiphertext(int keySizeInBytes, int ivSizeInBytes) throws Exception {
    byte[] aad = new byte[] {1, 2, 3};
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
}
