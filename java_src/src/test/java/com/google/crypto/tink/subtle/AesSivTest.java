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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for AesSiv */
@RunWith(JUnit4.class)
public class AesSivTest {

  private Integer[] keySizeInBytes;

  @Before
  public void setUp() throws Exception {
    if (Cipher.getMaxAllowedKeyLength("AES") < 256) {
      System.out.println(
          "Unlimited Strength Jurisdiction Policy Files are required"
              + " but not installed. Skip most AesSiv tests.");
      keySizeInBytes = new Integer[] {};
    } else {
      keySizeInBytes = new Integer[] {64};
    }
  }

  @Test
  public void testWycheproofVectors() throws Exception {
    JsonObject json =
        WycheproofTestUtil.readJson("../wycheproof/testvectors/aes_siv_cmac_test.json");
    JsonArray testGroups = json.getAsJsonArray("testGroups");
    int cntSkippedTests = 0;
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      int keySize = group.get("keySize").getAsInt();
      JsonArray tests = group.getAsJsonArray("tests");
      if (!Arrays.asList(keySizeInBytes).contains(keySize / 8)) {
        cntSkippedTests += tests.size();
        continue;
      }
      for (int j = 0; j < tests.size(); j++) {
        JsonObject testcase = tests.get(j).getAsJsonObject();
        String tcId =
            String.format(
                "testcase %d (%s)",
                testcase.get("tcId").getAsInt(), testcase.get("comment").getAsString());
        byte[] key = Hex.decode(testcase.get("key").getAsString());
        byte[] msg = Hex.decode(testcase.get("msg").getAsString());
        byte[] aad = Hex.decode(testcase.get("aad").getAsString());
        byte[] ct = Hex.decode(testcase.get("ct").getAsString());
        // Result is one of "valid" and "invalid".
        // "valid" are test vectors with matching plaintext and ciphertext.
        // "invalid" are test vectors with invalid parameters or invalid ciphertext.
        String result = testcase.get("result").getAsString();
        DeterministicAead daead = new AesSiv(key);
        if (result.equals("valid")) {
          byte[] ciphertext = daead.encryptDeterministically(msg, aad);
          assertEquals(tcId, Hex.encode(ct), Hex.encode(ciphertext));
          byte[] plaintext = daead.decryptDeterministically(ct, aad);
          assertEquals(tcId, Hex.encode(msg), Hex.encode(plaintext));
        } else {
          try {
            byte[] plaintext = daead.decryptDeterministically(ct, aad);
            fail(
                String.format(
                    "FAIL %s: decrypted invalid ciphertext as %s", tcId, Hex.encode(plaintext)));
          } catch (GeneralSecurityException ex) {
            // This is expected
          }
        }
      }
    }
    System.out.printf("Number of tests skipped: %d", cntSkippedTests);
  }

  @Test
  public void testEncryptDecryptWithEmptyPlaintext() throws GeneralSecurityException {
    for (int keySize : keySizeInBytes) {
      DeterministicAead dead = new AesSiv(Random.randBytes(keySize));
      for (int triesPlaintext = 0; triesPlaintext < 100; triesPlaintext++) {
        byte[] plaintext = new byte[0];
        byte[] aad = Random.randBytes(Random.randInt(128) + 1);
        byte[] ciphertext = dead.encryptDeterministically(plaintext, aad);
        byte[] rebuiltPlaintext = dead.decryptDeterministically(ciphertext, aad);
        assertThat(ciphertext).hasLength(AesUtil.BLOCK_SIZE);
        assertEquals(Hex.encode(plaintext), Hex.encode(rebuiltPlaintext));
      }
    }
  }

  @Test
  public void testEncryptDecryptWithEmptyAssociatedData() throws GeneralSecurityException {
    for (int keySize : keySizeInBytes) {
      DeterministicAead dead = new AesSiv(Random.randBytes(keySize));
      for (int triesPlaintext = 0; triesPlaintext < 100; triesPlaintext++) {
        byte[] plaintext = Random.randBytes(Random.randInt(1024) + 1);
        byte[] aad = new byte[0];
        byte[] rebuiltPlaintext =
            dead.decryptDeterministically(dead.encryptDeterministically(plaintext, aad), aad);
        assertEquals(Hex.encode(plaintext), Hex.encode(rebuiltPlaintext));
      }
    }
  }

  @Test
  public void testEncryptDecryptWithEmptyPlaintextAndEmptyAssociatedData()
      throws GeneralSecurityException {
    for (int keySize : keySizeInBytes) {
      DeterministicAead dead = new AesSiv(Random.randBytes(keySize));
      for (int triesPlaintext = 0; triesPlaintext < 100; triesPlaintext++) {
        byte[] plaintext = new byte[0];
        byte[] aad = new byte[0];
        byte[] rebuiltPlaintext =
            dead.decryptDeterministically(dead.encryptDeterministically(plaintext, aad), aad);
        assertEquals(Hex.encode(plaintext), Hex.encode(rebuiltPlaintext));
      }
    }
  }

  @Test
  public void testEncryptDecryptWithNullAssociatedData() throws GeneralSecurityException {
    for (int keySize : keySizeInBytes) {
      DeterministicAead dead = new AesSiv(Random.randBytes(keySize));
      for (int triesPlaintext = 0; triesPlaintext < 100; triesPlaintext++) {
        byte[] plaintext = Random.randBytes(Random.randInt(1024) + 1);
        byte[] rebuiltPlaintext =
            dead.decryptDeterministically(dead.encryptDeterministically(plaintext, null), null);
        assertEquals(Hex.encode(plaintext), Hex.encode(rebuiltPlaintext));
      }
    }
  }

  @Test
  public void testEncryptDecryptWithNullAndEmptyAssociatedDataEquivalent()
      throws GeneralSecurityException {
    for (int keySize : keySizeInBytes) {
      DeterministicAead dead = new AesSiv(Random.randBytes(keySize));
      for (int triesPlaintext = 0; triesPlaintext < 100; triesPlaintext++) {
        byte[] plaintext = Random.randBytes(Random.randInt(1024) + 1);
        byte[] emptyAad = new byte[0];
        byte[] emptyAadCiphertext = dead.encryptDeterministically(plaintext, emptyAad);
        byte[] emptyAadRebuiltPlaintext =
                dead.decryptDeterministically(emptyAadCiphertext, emptyAad);

        byte[] nullAadCipherText = dead.encryptDeterministically(plaintext, null);
        byte[] nullAadRebuiltPlaintext =
                dead.decryptDeterministically(nullAadCipherText, null);
        
        assertEquals(Hex.encode(plaintext), Hex.encode(emptyAadRebuiltPlaintext));
        assertEquals(Hex.encode(plaintext), Hex.encode(nullAadRebuiltPlaintext));
        assertEquals(Hex.encode(emptyAadCiphertext), Hex.encode(nullAadCipherText));
      }
    }
  }

  @Test
  public void testEncryptDecryptWithEmptyPlaintextAndNullAssociatedData()
      throws GeneralSecurityException {
    for (int keySize : keySizeInBytes) {
      DeterministicAead dead = new AesSiv(Random.randBytes(keySize));
      for (int triesPlaintext = 0; triesPlaintext < 100; triesPlaintext++) {
        byte[] plaintext = new byte[0];
        byte[] rebuiltPlaintext =
                dead.decryptDeterministically(dead.encryptDeterministically(plaintext, null), null);
        assertEquals(Hex.encode(plaintext), Hex.encode(rebuiltPlaintext));
      }
    }
  }

  @Test
  public void testEncryptDecrypt() throws GeneralSecurityException {
    for (int keySize : keySizeInBytes) {
      DeterministicAead dead = new AesSiv(Random.randBytes(keySize));

      for (int triesPlaintext = 0; triesPlaintext < 100; triesPlaintext++) {
        byte[] plaintext = Random.randBytes(Random.randInt(1024) + 1);
        byte[] aad = Random.randBytes(Random.randInt(128) + 1);
        byte[] rebuiltPlaintext =
            dead.decryptDeterministically(dead.encryptDeterministically(plaintext, aad), aad);
        assertEquals(Hex.encode(plaintext), Hex.encode(rebuiltPlaintext));
      }
    }
  }

  private static void testModifiedCiphertext(int keySize) throws GeneralSecurityException {
    byte[] key = Random.randBytes(keySize);
    DeterministicAead crypter = new AesSiv(key);
    byte[] plaintext = Random.randBytes(10);
    byte[] aad = Random.randBytes(10);
    byte[] ciphertext = crypter.encryptDeterministically(plaintext, aad);
    // Flipping bits of ciphertext.
    for (int b = 0; b < ciphertext.length; b++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modified = Arrays.copyOf(ciphertext, ciphertext.length);
        modified[b] ^= (byte) (1 << bit);
        try {
          byte[] unused = crypter.decryptDeterministically(modified, aad);
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
        byte[] unused = crypter.decryptDeterministically(modified, aad);
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
  public void testModifiedCiphertext() throws GeneralSecurityException {
    for (int keySize : keySizeInBytes) {
      testModifiedCiphertext(keySize);
    }
  }

  private static void testModifiedAssociatedData(int keySize) throws GeneralSecurityException {
    byte[] key = Random.randBytes(keySize);
    DeterministicAead crypter = new AesSiv(key);
    byte[] plaintext = Random.randBytes(10);
    byte[] aad = Random.randBytes(10);
    byte[] ciphertext = crypter.encryptDeterministically(plaintext, aad);
    // Flipping bits of aad.
    for (int b = 0; b < aad.length; b++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modified = Arrays.copyOf(aad, aad.length);
        modified[b] ^= (byte) (1 << bit);
        try {
          byte[] unused = crypter.decryptDeterministically(ciphertext, modified);
          fail("Decrypting modified aad should fail");
        } catch (AEADBadTagException ex) {
          // This is expected.
        }
      }
    }
  }

  @Test
  public void testModifiedAssociatedData() throws GeneralSecurityException {
    for (int keySize : keySizeInBytes) {
      testModifiedAssociatedData(keySize);
    }
  }

  @Test
  public void testInvalidKeySizes() throws GeneralSecurityException {
    try {
      // AesSiv doesn't accept 32-byte keys.
      new AesSiv(Random.randBytes(32));
      fail("32-byte keys should not be accepted");
    } catch (InvalidKeyException ex) {
      // expected.
    }

    for (int j = 0; j < 100; j++) {
      if (j == 48 || j == 64) {
        continue;
      }

      try {
        new AesSiv(Random.randBytes(j));
        fail("Keys with invalid size should not be accepted: " + j);
      } catch (InvalidKeyException ex) {
        // expected.
      }
    }
  }
}
