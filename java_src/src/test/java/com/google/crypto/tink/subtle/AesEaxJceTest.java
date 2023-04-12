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
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for AesEax. */
@RunWith(Theories.class)
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
    testModifyCiphertext(32, 16);
    testModifyCiphertext(32, 12);
  }

  public void testModifyCiphertext(int keySizeInBytes, int ivSizeInBytes) throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] aad = new byte[] {1, 2, 3};
    byte[] key = Random.randBytes(keySizeInBytes);
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

  private static class TestVector {
    public TestVector(
        String hexMessage, String hexKey, String hexNonce, String hexAad, String hexCiphertext) {
      this.hexMessage = hexMessage;
      this.hexKey = hexKey;
      this.hexNonce = hexNonce;
      this.hexAad = hexAad;
      this.hexCiphertext = hexCiphertext;
    }

    public final String hexMessage;
    public final String hexKey;
    public final String hexNonce;
    public final String hexAad;
    public final String hexCiphertext;
  }

  @DataPoints("testVectors")
  // Test vectors from "The EAX Mode of Operation", Appendix G.
  public static final TestVector[] TEST_VECTORS =
      new TestVector[] {
        new TestVector(
            "",
            "233952dee4d5ed5f9b9c6d6ff80ff478",
            "62ec67f9c3a4a407fcb2a8c49031a8b3",
            "6bfb914fd07eae6b",
            "e037830e8389f27b025a2d6527e79d01"),
        new TestVector(
            "f7fb",
            "91945d3f4dcbee0bf45ef52255f095a4",
            "becaf043b0a23d843194ba972c66debd",
            "fa3bfd4806eb53fa",
            "19dd5c4c9331049d0bdab0277408f67967e5"),
        new TestVector(
            "481c9e39b1",
            "d07cf6cbb7f313bdde66b727afd3c5e8",
            "8408dfff3c1a2b1292dc199e46b7d617",
            "33cce2eabff5a79d",
            "632a9d131ad4c168a4225d8e1ff755939974a7bede"),
        new TestVector(
            "40d0c07da5e4",
            "35b6d0580005bbc12b0587124557d2c2",
            "fdb6b06676eedc5c61d74276e1f8e816",
            "aeb96eaebe2970e9",
            "071dfe16c675cb0677e536f73afe6a14b74ee49844dd"),
        new TestVector(
            "4de3b35c3fc039245bd1fb7d",
            "bd8e6e11475e60b268784c38c62feb22",
            "6eac5c93072d8e8513f750935e46da1b",
            "d4482d1ca78dce0f",
            "835bb4f15d743e350e728414abb8644fd6ccb86947c5e10590210a4f"),
        new TestVector(
            "8b0a79306c9ce7ed99dae4f87f8dd61636",
            "7c77d6e813bed5ac98baa417477a2e7d",
            "1a8c98dcd73d38393b2bf1569deefc19",
            "65d2017990d62528",
            "02083e3979da014812f59f11d52630da30137327d10649b0aa6e1c181db617d7f2"),
        new TestVector(
            "1bda122bce8a8dbaf1877d962b8592dd2d56",
            "5fff20cafab119ca2fc73549e20f5b0d",
            "dde59b97d722156d4d9aff2bc7559826",
            "54b9f04e6a09189a",
            "2ec47b2c4954a489afc7ba4897edcdae8cc33b60450599bd02c96382902aef7f832a"),
        new TestVector(
            "6cf36720872b8513f6eab1a8a44438d5ef11",
            "a4a4782bcffd3ec5e7ef6d8c34a56123",
            "b781fcf2f75fa5a8de97a9ca48e522ec",
            "899a175897561d7e",
            "0de18fd0fdd91e7af19f1d8ee8733938b1e8e7f6d2231618102fdb7fe55ff1991700"),
        new TestVector(
            "ca40d7446e545ffaed3bd12a740a659ffbbb3ceab7",
            "8395fcf1e95bebd697bd010bc766aac3",
            "22e7add93cfc6393c57ec0b3c17d6b44",
            "126735fcc320d25a",
            "cb8920f87a6c75cff39627b56e3ed197c552d295a7cfc46afc253b4652b1af3795b124ab6e")
      };

  @Theory
  public void testVector_decrypt_works(@FromDataPoints("testVectors") TestVector vector)
      throws Exception {
    // We cannot use "Assume" here because Theories will complain that no input does any test.
    if (TinkFips.useOnlyFips()) {
      return;
    }
    byte[] fullCiphertext = Hex.decode(vector.hexNonce + vector.hexCiphertext);
    AesEaxJce eax = new AesEaxJce(Hex.decode(vector.hexKey), Hex.decode(vector.hexNonce).length);
    byte[] decryption = eax.decrypt(fullCiphertext, Hex.decode(vector.hexAad));
    assertThat(Hex.encode(decryption)).isEqualTo(vector.hexMessage);
  }
}
