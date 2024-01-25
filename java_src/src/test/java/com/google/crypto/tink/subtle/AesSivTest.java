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
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.daead.AesSivKey;
import com.google.crypto.tink.daead.AesSivParameters;
import com.google.crypto.tink.mac.internal.AesUtil;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.crypto.tink.util.SecretBytes;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import org.junit.Assume;
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
      keySizeInBytes = new Integer[] {64};
  }

  @Test
  public void testWycheproofVectors() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

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
          assertThrows(
              String.format("FAIL %s: decrypted invalid ciphertext", tcId),
              GeneralSecurityException.class,
              () -> daead.decryptDeterministically(ct, aad));
        }
      }
    }
    System.out.printf("Number of tests skipped: %d", cntSkippedTests);
  }

  @Test
  public void testWycheproofVectors_createNoPrefix() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

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
        AesSivParameters parameters =
            AesSivParameters.builder()
                .setKeySizeBytes(64)
                .setVariant(AesSivParameters.Variant.NO_PREFIX)
                .build();
        SecretBytes keyBytes = SecretBytes.copyFrom(key, InsecureSecretKeyAccess.get());
        AesSivKey aesSivKey =
            AesSivKey.builder().setParameters(parameters).setKeyBytes(keyBytes).build();
        DeterministicAead daead = AesSiv.create(aesSivKey);
        if (result.equals("valid")) {
          byte[] ciphertext = daead.encryptDeterministically(msg, aad);
          assertEquals(tcId, Hex.encode(ct), Hex.encode(ciphertext));
          byte[] plaintext = daead.decryptDeterministically(ct, aad);
          assertEquals(tcId, Hex.encode(msg), Hex.encode(plaintext));
        } else {
          assertThrows(
              String.format("FAIL %s: decrypted invalid ciphertext", tcId),
              GeneralSecurityException.class,
              () -> daead.decryptDeterministically(ct, aad));
        }
      }
    }
    System.out.printf("Number of tests skipped: %d", cntSkippedTests);
  }

  @Test
  public void testEncryptDecryptWithEmptyPlaintext() throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());

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
    Assume.assumeFalse(TinkFips.useOnlyFips());

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
    Assume.assumeFalse(TinkFips.useOnlyFips());

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
    Assume.assumeFalse(TinkFips.useOnlyFips());

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
    Assume.assumeFalse(TinkFips.useOnlyFips());

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
    Assume.assumeFalse(TinkFips.useOnlyFips());

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
    Assume.assumeFalse(TinkFips.useOnlyFips());

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
    Assume.assumeFalse(TinkFips.useOnlyFips());

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
    Assume.assumeFalse(TinkFips.useOnlyFips());

    for (int keySize : keySizeInBytes) {
      testModifiedCiphertext(keySize);
    }
  }

  private static void testModifiedAssociatedData(int keySize) throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());

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
    Assume.assumeFalse(TinkFips.useOnlyFips());

    for (int keySize : keySizeInBytes) {
      testModifiedAssociatedData(keySize);
    }
  }

  @Test
  public void testInvalidKeySizes() throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    assertThrows(InvalidKeyException.class, () -> new AesSiv(Random.randBytes(32)));

    for (int i = 0; i < 100; i++) {
      final int j = i;
      if (j == 48 || j == 64) {
        continue;
      }

      assertThrows(
          "Keys with invalid size should not be accepted: " + j,
          InvalidKeyException.class,
          () -> new AesSiv(Random.randBytes(j)));
    }
  }

  @Test
  public void testFailIfFipsModuleNotAvailable() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());

    byte[] key = Random.randBytes(16);
    assertThrows(GeneralSecurityException.class, () -> new AesSiv(key));
  }

  @Test
  public void testCreate_constructor_singleTest() throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());
    byte[] key =
        Hex.decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");

    DeterministicAead daead = new AesSiv(key);
    assertThat(daead.encryptDeterministically(Hex.decode(""), Hex.decode("FF")))
        .isEqualTo(Hex.decode("1BC49C6A894EF5744A0A01D46608CBCC"));
    assertThat(
            daead.decryptDeterministically(
                Hex.decode("1BC49C6A894EF5744A0A01D46608CBCC"), Hex.decode("FF")))
        .isEqualTo(Hex.decode(""));
  }

  /** Same value as in testCreate_constructor_singleTest. */
  @Test
  public void testCreateForEncryptConstructorForDecrypt_noPrefix() throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());
    AesSivParameters parameters =
        AesSivParameters.builder()
            .setKeySizeBytes(64)
            .setVariant(AesSivParameters.Variant.NO_PREFIX)
            .build();
    SecretBytes keyBytes =
        SecretBytes.copyFrom(
            Hex.decode(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                    + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
            InsecureSecretKeyAccess.get());

    AesSivKey key = AesSivKey.builder().setParameters(parameters).setKeyBytes(keyBytes).build();
    DeterministicAead daead = AesSiv.create(key);
    assertThat(daead.encryptDeterministically(Hex.decode(""), Hex.decode("FF")))
        .isEqualTo(Hex.decode("1BC49C6A894EF5744A0A01D46608CBCC"));
    assertThat(
            daead.decryptDeterministically(
                Hex.decode("1BC49C6A894EF5744A0A01D46608CBCC"), Hex.decode("FF")))
        .isEqualTo(Hex.decode(""));
  }

  @Test
  public void testCreateForEncryptConstructorForDecrypt_tinkPrefix()
      throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());
    AesSivParameters parameters =
        AesSivParameters.builder()
            .setKeySizeBytes(64)
            .setVariant(AesSivParameters.Variant.TINK)
            .build();
    SecretBytes keyBytes =
        SecretBytes.copyFrom(
            Hex.decode(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                    + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
            InsecureSecretKeyAccess.get());

    AesSivKey key =
        AesSivKey.builder()
            .setParameters(parameters)
            .setKeyBytes(keyBytes)
            .setIdRequirement(0x44556677)
            .build();
    DeterministicAead daead = AesSiv.create(key);
    assertThat(daead.encryptDeterministically(Hex.decode(""), Hex.decode("FF")))
        .isEqualTo(Hex.decode("01445566771BC49C6A894EF5744A0A01D46608CBCC"));
    assertThat(
            daead.decryptDeterministically(
                Hex.decode("01445566771BC49C6A894EF5744A0A01D46608CBCC"), Hex.decode("FF")))
        .isEqualTo(Hex.decode(""));
  }

  @Test
  public void testCreateForEncryptConstructorForDecrypt_crunchyPrefix()
      throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());
    AesSivParameters parameters =
        AesSivParameters.builder()
            .setKeySizeBytes(64)
            .setVariant(AesSivParameters.Variant.CRUNCHY)
            .build();
    SecretBytes keyBytes =
        SecretBytes.copyFrom(
            Hex.decode(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                    + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
            InsecureSecretKeyAccess.get());

    AesSivKey key =
        AesSivKey.builder()
            .setParameters(parameters)
            .setKeyBytes(keyBytes)
            .setIdRequirement(0x44556677)
            .build();
    DeterministicAead daead = AesSiv.create(key);
    assertThat(daead.encryptDeterministically(Hex.decode(""), Hex.decode("FF")))
        .isEqualTo(Hex.decode("00445566771BC49C6A894EF5744A0A01D46608CBCC"));
    assertThat(
            daead.decryptDeterministically(
                Hex.decode("00445566771BC49C6A894EF5744A0A01D46608CBCC"), Hex.decode("FF")))
        .isEqualTo(Hex.decode(""));
  }

  @Test
  public void testKeySize32_throws() throws GeneralSecurityException {
    AesSivParameters parameters =
        AesSivParameters.builder()
            .setKeySizeBytes(32)
            .setVariant(AesSivParameters.Variant.TINK)
            .build();
    SecretBytes keyBytes = SecretBytes.randomBytes(32);

    AesSivKey key =
        AesSivKey.builder()
            .setParameters(parameters)
            .setKeyBytes(keyBytes)
            .setIdRequirement(0x44556677)
            .build();
    assertThrows(GeneralSecurityException.class, () -> AesSiv.create(key));
  }

  @Test
  public void testKeySize48_throws() throws GeneralSecurityException {
    AesSivParameters parameters =
        AesSivParameters.builder()
            .setKeySizeBytes(48)
            .setVariant(AesSivParameters.Variant.NO_PREFIX)
            .build();
    SecretBytes keyBytes = SecretBytes.randomBytes(48);

    AesSivKey key = AesSivKey.builder().setParameters(parameters).setKeyBytes(keyBytes).build();
    assertThrows(GeneralSecurityException.class, () -> AesSiv.create(key));
  }

  @Test
  public void testCreateThrowsInFipsMode() throws GeneralSecurityException {
    Assume.assumeTrue(TinkFips.useOnlyFips());
    AesSivParameters parameters =
        AesSivParameters.builder()
            .setKeySizeBytes(64)
            .setVariant(AesSivParameters.Variant.NO_PREFIX)
            .build();
    SecretBytes keyBytes =
        SecretBytes.copyFrom(
            Hex.decode(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                    + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
            InsecureSecretKeyAccess.get());
    AesSivKey key = AesSivKey.builder().setParameters(parameters).setKeyBytes(keyBytes).build();
    assertThrows(GeneralSecurityException.class, () -> AesSiv.create(key));
  }
}
