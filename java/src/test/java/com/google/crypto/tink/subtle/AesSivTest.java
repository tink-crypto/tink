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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.WycheproofTestUtil;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import org.json.JSONArray;
import org.json.JSONObject;
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
    } else if (TestUtil.isAndroid()) {
      // Conscrypt on Android does not support 192-bit keys.
      keySizeInBytes = new Integer[] {64};
    } else {
      keySizeInBytes = new Integer[] {48, 64};
    }
  }

  @Test
  public void testWycheproofVectors() throws Exception {
    JSONObject json = WycheproofTestUtil.readJson("testdata/wycheproof/aes_siv_cmac_test.json");
    WycheproofTestUtil.checkAlgAndVersion(json, "AES-SIV-CMAC", "0.1.6");
    JSONArray testGroups = json.getJSONArray("testGroups");
    for (int i = 0; i < testGroups.length(); i++) {
      JSONObject group = testGroups.getJSONObject(i);
      int keySize = group.getInt("keySize");
      JSONArray tests = group.getJSONArray("tests");
      if (!Arrays.asList(keySizeInBytes).contains(keySize / 8)) {
        System.out.println("Skipping tests with key size: " + keySize);
        continue;
      }
      for (int j = 0; j < tests.length(); j++) {
        JSONObject testcase = tests.getJSONObject(j);
        int tcid = testcase.getInt("tcId");
        String comment = "tcId: " + tcid + " " + testcase.getString("comment");
        byte[] key = Hex.decode(testcase.getString("key"));
        byte[] msg = Hex.decode(testcase.getString("msg"));
        byte[] aad = Hex.decode(testcase.getString("aad"));
        byte[] ct = Hex.decode(testcase.getString("ct"));
        // Result is one of "valid" and "invalid".
        // "valid" are test vectors with matching plaintext and ciphertext.
        // "invalid" are test vectors with invalid parameters or invalid ciphertext.
        String result = testcase.getString("result");

        DeterministicAead daead = new AesSiv(key);
        if (result.equals("valid")) {
          byte[] ciphertext = daead.encryptDeterministically(msg, aad);
          assertEquals(comment, Hex.encode(ct), Hex.encode(ciphertext));
          byte[] plaintext = daead.decryptDeterministically(ct, aad);
          assertEquals(comment, Hex.encode(msg), Hex.encode(plaintext));
        } else {
          try {
            byte[] plaintext = daead.decryptDeterministically(ct, aad);
            fail("Decrypted invalid ciphertext:" + comment + " as:" + Hex.encode(plaintext));
          } catch (GeneralSecurityException ex) {
            // This is expected
          }
        }
      }
    }
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
        assertEquals(AesUtil.BLOCK_SIZE, ciphertext.length);
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
