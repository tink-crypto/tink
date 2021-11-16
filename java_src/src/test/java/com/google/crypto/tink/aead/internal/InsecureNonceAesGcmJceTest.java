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
import static org.junit.Assert.fail;

import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.SubtleUtil;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.testing.TestUtil.BytesMutation;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Arrays;
import java.util.HashSet;
import javax.crypto.Cipher;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link InsecureNonceAesGcmJce}. */
@RunWith(JUnit4.class)
public class InsecureNonceAesGcmJceTest {

  private Integer[] keySizeInBytes;

  @Before
  public void setUp() throws Exception {
    if (Cipher.getMaxAllowedKeyLength("AES") < 256) {
      System.out.println(
          "Unlimited Strength Jurisdiction Policy Files are required"
              + " but not installed. Skip tests with keys larger than 128 bits.");
      keySizeInBytes = new Integer[] {16};
    } else {
      keySizeInBytes = new Integer[] {16, 32};
    }
  }

  @Before
  public void useConscrypt() throws Exception {
    // If Tink is build in FIPS-only mode, then we register Conscrypt for the tests.
    if (TinkFips.useOnlyFips()) {
      try {
        Conscrypt.checkAvailability();
        Security.addProvider(Conscrypt.newProvider());
      } catch (Throwable cause) {
        throw new IllegalStateException(
            "Cannot test AesGcm in FIPS-mode without Conscrypt Provider", cause);
      }
    }
  }

  @Test
  public void testEncryptDecrypt_withPrependedIv() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    byte[] aad = generateAad();
    for (int keySize : keySizeInBytes) {
      byte[] key = Random.randBytes(keySize);
      InsecureNonceAesGcmJce gcm = new InsecureNonceAesGcmJce(key, /*prependIv=*/ true);
      for (int messageSize = 0; messageSize < 75; messageSize++) {
        byte[] message = Random.randBytes(messageSize);
        byte[] iv = Random.randBytes(InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);
        byte[] ciphertext = gcm.encrypt(iv, message, aad);
        byte[] decrypted = gcm.decrypt(iv, ciphertext, aad);
        assertArrayEquals(message, decrypted);
      }
    }
  }

  @Test
  public void testEncryptDecrypt_withoutPrependedIv() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    byte[] aad = generateAad();
    for (int keySize : keySizeInBytes) {
      byte[] key = Random.randBytes(keySize);
      InsecureNonceAesGcmJce gcm = new InsecureNonceAesGcmJce(key, /*prependIv=*/ false);
      for (int messageSize = 0; messageSize < 75; messageSize++) {
        byte[] message = Random.randBytes(messageSize);
        byte[] iv = Random.randBytes(InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);
        byte[] ciphertext = gcm.encrypt(iv, message, aad);
        byte[] decrypted = gcm.decrypt(iv, ciphertext, aad);
        assertArrayEquals(message, decrypted);
      }
    }
  }

  @Test
  public void testEncryptWithAad_shouldFailOnAndroid19OrOlder() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());
    Assume.assumeFalse(!SubtleUtil.isAndroid() || SubtleUtil.androidApiLevel() > 19);

    InsecureNonceAesGcmJce gcm =
        new InsecureNonceAesGcmJce(Random.randBytes(16), /*prependIv=*/ false);
    byte[] message = Random.randBytes(20);
    byte[] aad = Random.randBytes(20);
    byte[] iv = Random.randBytes(InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);

    assertThrows(UnsupportedOperationException.class, () -> gcm.encrypt(iv, message, aad));
  }

  @Test
  /** BC had a bug, where GCM failed for messages of size > 8192 */
  public void testLongMessages() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());
    Assume.assumeFalse(TestUtil.isAndroid()); // doesn't work on Android

    int dataSize = 16;
    while (dataSize <= (1 << 24)) {
      byte[] plaintext = Random.randBytes(dataSize);
      byte[] aad = Random.randBytes(dataSize / 3);
      for (int keySize : keySizeInBytes) {
        byte[] key = Random.randBytes(keySize);
        InsecureNonceAesGcmJce gcm = new InsecureNonceAesGcmJce(key, /*prependIv=*/ false);
        byte[] iv = Random.randBytes(InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);
        byte[] ciphertext = gcm.encrypt(iv, plaintext, aad);
        byte[] decrypted = gcm.decrypt(iv, ciphertext, aad);
        assertArrayEquals(plaintext, decrypted);
      }
      dataSize += 5 * dataSize / 11;
    }
  }

  @Test
  public void testModifyCiphertext() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    byte[] aad = generateAad();
    byte[] key = Random.randBytes(16);
    byte[] message = Random.randBytes(32);
    InsecureNonceAesGcmJce gcm = new InsecureNonceAesGcmJce(key, /*prependIv=*/ false);
    byte[] iv = Random.randBytes(InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);
    byte[] ciphertext = gcm.encrypt(iv, message, aad);

    for (BytesMutation mutation : TestUtil.generateMutations(ciphertext)) {
      assertThrows(
          String.format(
              "Decrypting modified ciphertext should fail : ciphertext = %s, aad = %s,"
                  + " description = %s",
              Hex.encode(mutation.value), Hex.encode(aad), mutation.description),
          GeneralSecurityException.class,
          () -> {
            byte[] unused = gcm.decrypt(iv, mutation.value, aad);
          });
    }

    // Modify AAD
    if (aad != null && aad.length != 0) {
      for (BytesMutation mutation : TestUtil.generateMutations(aad)) {
        assertThrows(
            String.format(
                "Decrypting with modified aad should fail: ciphertext = %s, aad = %s,"
                    + " description = %s",
                Arrays.toString(ciphertext), Arrays.toString(mutation.value), mutation.description),
            GeneralSecurityException.class,
            () -> {
              byte[] unused = gcm.decrypt(iv, ciphertext, mutation.value);
            });
      }
    }
  }

  @Test
  public void testWycheproofVectors() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    JsonObject json =
        WycheproofTestUtil.readJson("../wycheproof/testvectors/aes_gcm_test.json");
    int errors = 0;
    int cntSkippedTests = 0;
    JsonArray testGroups = json.get("testGroups").getAsJsonArray();
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      int keySize = group.get("keySize").getAsInt();
      JsonArray tests = group.get("tests").getAsJsonArray();
      if (!Arrays.asList(keySizeInBytes).contains(keySize / 8)) {
        cntSkippedTests += tests.size();
        continue;
      }
      for (int j = 0; j < tests.size(); j++) {
        JsonObject testcase = tests.get(j).getAsJsonObject();
        String tcId =
            String.format("testcase %d (%s)",
                testcase.get("tcId").getAsInt(), testcase.get("comment").getAsString());
        byte[] iv = Hex.decode(testcase.get("iv").getAsString());
        byte[] key = Hex.decode(testcase.get("key").getAsString());
        byte[] msg = Hex.decode(testcase.get("msg").getAsString());
        byte[] aad = Hex.decode(testcase.get("aad").getAsString());
        if (SubtleUtil.isAndroid() && SubtleUtil.androidApiLevel() <= 19 && aad.length != 0) {
          cntSkippedTests++;
          continue;
        }
        byte[] ct = Hex.decode(testcase.get("ct").getAsString());
        byte[] tag = Hex.decode(testcase.get("tag").getAsString());
        byte[] ciphertext = Bytes.concat(ct, tag);
        // Result is one of "valid", "invalid", "acceptable".
        // "valid" are test vectors with matching plaintext, ciphertext and tag.
        // "invalid" are test vectors with invalid parameters or invalid ciphertext and tag.
        // "acceptable" are test vectors with weak parameters or legacy formats.
        String result = testcase.get("result").getAsString();
        // Tink only supports 12-byte iv.
        if (iv.length != 12) {
          result = "invalid";
        }

        try {
          InsecureNonceAesGcmJce gcm = new InsecureNonceAesGcmJce(key, /*prependIv=*/ false);
          // Encryption.
          byte[] encrypted = gcm.encrypt(iv, msg, aad);
          boolean ciphertextMatches = TestUtil.arrayEquals(encrypted, ciphertext);
          if (result.equals("valid") && !ciphertextMatches) {
            System.out.printf(
                "FAIL %s: incorrect encryption, result: %s, expected: %s%n",
                tcId, Hex.encode(encrypted), Hex.encode(ciphertext));
            errors++;
          }
          // Decryption.
          byte[] decrypted = gcm.decrypt(iv, ciphertext, aad);
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
    System.out.printf("Number of tests skipped: %d", cntSkippedTests);
    assertEquals(0, errors);
  }

  @Test
  public void testNullPlaintextOrCiphertext() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    for (int keySize : keySizeInBytes) {
      InsecureNonceAesGcmJce gcm =
          new InsecureNonceAesGcmJce(Random.randBytes(keySize), /*prependIv=*/ false);
      byte[] aad = generateAad();
      byte[] iv = Random.randBytes(InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);
      assertThrows(
          NullPointerException.class,
          () -> {
            byte[] unused = gcm.encrypt(iv, null, aad);
          });
      assertThrows(
          NullPointerException.class,
          () -> {
            byte[] unused = gcm.encrypt(iv, null, null);
          });
      assertThrows(
          NullPointerException.class,
          () -> {
            byte[] unused = gcm.decrypt(iv, null, aad);
          });
      assertThrows(
          NullPointerException.class,
          () -> {
            byte[] unused = gcm.decrypt(iv, null, null);
          });
    }
  }

  @Test
  public void testEmptyAssociatedData() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    byte[] aad = new byte[0];
    for (int keySize : keySizeInBytes) {
      byte[] key = Random.randBytes(keySize);
      InsecureNonceAesGcmJce gcm = new InsecureNonceAesGcmJce(key, /*prependIv=*/ false);
      for (int messageSize = 0; messageSize < 75; messageSize++) {
        byte[] message = Random.randBytes(messageSize);
        {  // encrypting with aad as a 0-length array
          byte[] iv = Random.randBytes(InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);
          byte[] ciphertext = gcm.encrypt(iv, message, aad);
          byte[] decrypted = gcm.decrypt(iv, ciphertext, aad);
          assertArrayEquals(message, decrypted);
          byte[] decrypted2 = gcm.decrypt(iv, ciphertext, null);
          assertArrayEquals(message, decrypted2);
          try {
            byte[] badAad = new byte[] {1, 2, 3};
            byte[] unused = gcm.decrypt(iv, ciphertext, badAad);
            fail("Decrypting with modified aad should fail");
          } catch (GeneralSecurityException ex) {
            // This is expected.
            // This could be a AeadBadTagException when the tag verification
            // fails or some not yet specified Exception when the ciphertext is too short.
            // In all cases a GeneralSecurityException or a subclass of it must be thrown.
          } catch (UnsupportedOperationException ex) {
            // Android API level <= 19 would throw this exception, as expected.
          }
        }
        {  // encrypting with aad equal to null
          byte[] iv = Random.randBytes(InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);
          byte[] ciphertext = gcm.encrypt(iv, message, null);
          byte[] decrypted = gcm.decrypt(iv, ciphertext, aad);
          assertArrayEquals(message, decrypted);
          byte[] decrypted2 = gcm.decrypt(iv, ciphertext, null);
          assertArrayEquals(message, decrypted2);
          try {
            byte[] badAad = new byte[] {1, 2, 3};
            byte[] unused = gcm.decrypt(iv, ciphertext, badAad);
            fail("Decrypting with modified aad should fail");
          } catch (GeneralSecurityException ex) {
            // This is expected.
            // This could be a AeadBadTagException when the tag verification
            // fails or some not yet specified Exception when the ciphertext is too short.
            // In all cases a GeneralSecurityException or a subclass of it must be thrown.
          } catch (UnsupportedOperationException ex) {
            // Android API level <= 19 would throw this exception, as expected.
          }
        }
      }
    }
  }

  @Test
  /**
   * This is a very simple test for the randomness of the nonce. The test simply checks that the
   * multiple ciphertexts of the same message are distinct.
   */
  public void testRandomNonce() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    final int samples = 1 << 17;
    byte[] key = Random.randBytes(16);
    byte[] message = new byte[0];
    byte[] aad = generateAad();
    InsecureNonceAesGcmJce gcm = new InsecureNonceAesGcmJce(key, /*prependIv=*/ false);
    HashSet<String> ciphertexts = new HashSet<>();
    for (int i = 0; i < samples; i++) {
      byte[] iv = Random.randBytes(InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);
      byte[] ct = gcm.encrypt(iv, message, aad);
      String ctHex = TestUtil.hexEncode(ct);
      assertThat(ciphertexts).doesNotContain(ctHex);
      ciphertexts.add(ctHex);
    }
  }

  private static byte[] generateAad() {
    byte[] aad = Random.randBytes(20);
    // AES-GCM on Android <= 19 doesn't support AAD. See last bullet point in
    // https://github.com/google/tink/blob/master/docs/KNOWN-ISSUES.md#android.
    if (SubtleUtil.isAndroid() && SubtleUtil.androidApiLevel() <= 19) {
      aad = new byte[0];
    }
    return aad;
  }

  @Test
  public void testFailIfFipsModuleNotAvailable() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable());

    byte[] key = Random.randBytes(16);
    assertThrows(
        GeneralSecurityException.class,
        () -> new InsecureNonceAesGcmJce(key, /*prependIv=*/ false));
  }
}
