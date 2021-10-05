// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.hybrid.internal;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.common.io.Files;
import com.google.common.io.Resources;
import com.google.common.truth.Expect;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.X25519;
import com.google.crypto.tink.testing.HpkeTestId;
import com.google.crypto.tink.testing.HpkeTestSetup;
import com.google.crypto.tink.testing.HpkeTestUtil;
import com.google.crypto.tink.testing.HpkeTestVector;
import com.google.crypto.tink.testing.TestUtil;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link HkdfHpkeKdf}. */
@RunWith(JUnit4.class)
public final class HkdfHpkeKdfTest {
  private static final int AES_128_GCM_KEY_LENGTH = 16; // Nk
  private static final int AES_128_GCM_NONCE_LENGTH = 12; // Nn
  private static final int X25519_HKDF_SHA256_KEM_SHARED_SECRET_LENGTH = 32; // Nsecret

  private static Map<HpkeTestId, HpkeTestVector> testVectors;

  @Rule public final Expect expect = Expect.create();

  @BeforeClass
  public static void setUpTestVectors() throws IOException {
    BufferedReader reader = null;
    if (TestUtil.isAndroid()) {
      reader =
          Files.newReader(
              new File(
                  "/sdcard/googletest/test_runfiles/google3/" // Special prefix for Android.
                      + "third_party/tink/java_src/src/test/java/com/google/crypto/tink/"
                      + "hybrid/internal/testdata/test_vectors.json"),
              UTF_8);
    } else {
      String path = "com/google/crypto/tink/hybrid/internal/testdata/test_vectors.json";
      reader = Resources.asCharSource(Resources.getResource(path), UTF_8).openBufferedStream();
    }
    testVectors = HpkeTestUtil.parseTestVectors(reader);
  }

  private HpkeTestSetup getTestSetup(byte[] mode, byte[] kemId, byte[] kdfId, byte[] aeadId) {
    HpkeTestId testId = new HpkeTestId(mode, kemId, kdfId, aeadId);
    return testVectors.get(testId).getTestSetup();
  }

  private void testExtract(HkdfHpkeKdf kdf, byte[] mode, byte[] kemId, byte[] kdfId, byte[] aeadId)
      throws GeneralSecurityException {
    HpkeTestSetup testSetup = getTestSetup(mode, kemId, kdfId, aeadId);
    byte[] suiteId = HpkeUtil.hpkeSuiteId(kemId, kdfId, aeadId);

    byte[] defaultPskId = new byte[0];
    byte[] pskIdHash =
        kdf.labeledExtract(HpkeUtil.EMPTY_SALT, defaultPskId, "psk_id_hash", suiteId);
    byte[] infoHash = kdf.labeledExtract(HpkeUtil.EMPTY_SALT, testSetup.info, "info_hash", suiteId);
    byte[] keyScheduleContext = Bytes.concat(mode, pskIdHash, infoHash);

    byte[] defaultPsk = new byte[0];
    byte[] secret = kdf.labeledExtract(testSetup.sharedSecret, defaultPsk, "secret", suiteId);

    expect.that(keyScheduleContext).isEqualTo(testSetup.keyScheduleContext);
    expect.that(secret).isEqualTo(testSetup.secret);
  }

  private void testExpand(
      HkdfHpkeKdf kdf,
      byte[] mode,
      byte[] kemId,
      byte[] kdfId,
      byte[] aeadId,
      int keyLength,
      int nonceLength)
      throws GeneralSecurityException {
    HpkeTestSetup testSetup = getTestSetup(mode, kemId, kdfId, aeadId);
    byte[] suiteId = HpkeUtil.hpkeSuiteId(kemId, kdfId, aeadId);

    byte[] key =
        kdf.labeledExpand(
            testSetup.secret, testSetup.keyScheduleContext, "key", suiteId, keyLength);
    byte[] baseNonce =
        kdf.labeledExpand(
            testSetup.secret, testSetup.keyScheduleContext, "base_nonce", suiteId, nonceLength);

    expect.that(key).isEqualTo(testSetup.key);
    expect.that(baseNonce).isEqualTo(testSetup.baseNonce);
  }

  private void testExtractAndExpand(
      HkdfHpkeKdf kdf, byte[] mode, byte[] kemId, byte[] kdfId, byte[] aeadId, int length)
      throws GeneralSecurityException {
    HpkeTestSetup testSetup = getTestSetup(mode, kemId, kdfId, aeadId);

    byte[] dhSharedSecret =
        X25519.computeSharedSecret(testSetup.senderPrivateKey, testSetup.recipientPublicKey);
    byte[] kemContext = Bytes.concat(testSetup.senderPublicKey, testSetup.recipientPublicKey);
    byte[] sharedSecret =
        kdf.extractAndExpand(
            HpkeUtil.EMPTY_SALT,
            dhSharedSecret,
            "eae_prk",
            kemContext,
            "shared_secret",
            HpkeUtil.kemSuiteId(kemId),
            length);

    expect.that(sharedSecret).isEqualTo(testSetup.sharedSecret);
  }

  @Test
  public void labeledExtract_hkdfSha256() throws GeneralSecurityException {
    HkdfHpkeKdf kdf = new HkdfHpkeKdf("HmacSha256");
    testExtract(
        kdf,
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.AES_128_GCM_AEAD_ID);
  }

  @Test
  public void labeledExtract_hkdfSha512() throws GeneralSecurityException {
    HkdfHpkeKdf kdf = new HkdfHpkeKdf("HmacSha512");
    testExtract(
        kdf,
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.intToByteArray(2, 0x3), // HKDF-SHA-512 algorithm identifier.
        HpkeUtil.AES_128_GCM_AEAD_ID);
  }

  @Test
  public void labeledExpand_hkdfSha256() throws GeneralSecurityException {
    HkdfHpkeKdf kdf = new HkdfHpkeKdf("HmacSha256");
    testExpand(
        kdf,
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.AES_128_GCM_AEAD_ID,
        AES_128_GCM_KEY_LENGTH,
        AES_128_GCM_NONCE_LENGTH);
  }

  @Test
  public void labeledExpand_hkdfSha512() throws GeneralSecurityException {
    HkdfHpkeKdf kdf = new HkdfHpkeKdf("HmacSha512");
    testExpand(
        kdf,
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.intToByteArray(2, 0x3), // HKDF-SHA-512 algorithm identifier.
        HpkeUtil.AES_128_GCM_AEAD_ID,
        AES_128_GCM_KEY_LENGTH,
        AES_128_GCM_NONCE_LENGTH);
  }

  @Test
  public void labeledExpand_outputLongerThanDigestLength() throws GeneralSecurityException {
    HkdfHpkeKdf kdf = new HkdfHpkeKdf("HmacSha256");
    byte[] suiteId =
        HpkeUtil.hpkeSuiteId(
            HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
            HpkeUtil.HKDF_SHA256_KDF_ID,
            HpkeUtil.AES_128_GCM_AEAD_ID);
    // Following values from https://datatracker.ietf.org/doc/html/rfc5869#appendix-A.1.
    byte[] prk = Hex.decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    byte[] info = Hex.decode("f0f1f2f3f4f5f6f7f8f9");
    int outputLength = 42;
    // Expected output was manually generated.
    byte[] expected =
        Hex.decode(
            "2f1a8eb86971cd1850d04a1b98f9a63d52d56c5a4d5fcb68103e57c7a85a1df2c9be1346ae041007712d");
    byte[] actual = kdf.labeledExpand(prk, info, "info_label", suiteId, outputLength);
    expect.that(actual).isEqualTo(expected);
  }

  @Test
  public void extractAndExpand_hkdfSha256() throws GeneralSecurityException {
    // NOTE: This test actually applies to the KEM scenario (i.e., X25519_HKDF_SHA256_KEM_ID),
    // rather than the KDF scenario (i.e., HKDF_SHA256_KDF_ID).
    HkdfHpkeKdf kdf = new HkdfHpkeKdf("HmacSha256");
    testExtractAndExpand(
        kdf,
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.AES_128_GCM_AEAD_ID,
        X25519_HKDF_SHA256_KEM_SHARED_SECRET_LENGTH);
  }

  @Test
  public void invalidMacAlgorithm() throws GeneralSecurityException {
    HkdfHpkeKdf kdf = new HkdfHpkeKdf("InvalidMacAlgorithm");
    HpkeTestSetup testSetup =
        getTestSetup(
            HpkeUtil.BASE_MODE,
            HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
            HpkeUtil.HKDF_SHA256_KDF_ID,
            HpkeUtil.AES_128_GCM_AEAD_ID);
    byte[] suiteId =
        HpkeUtil.hpkeSuiteId(
            HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
            HpkeUtil.HKDF_SHA256_KDF_ID,
            HpkeUtil.AES_128_GCM_AEAD_ID);
    assertThrows(
        NoSuchAlgorithmException.class,
        () -> kdf.labeledExtract(HpkeUtil.EMPTY_SALT, testSetup.info, "info_hash", suiteId));
    assertThrows(
        NoSuchAlgorithmException.class,
        () ->
            kdf.labeledExpand(
                testSetup.secret,
                testSetup.keyScheduleContext,
                "key",
                suiteId,
                X25519_HKDF_SHA256_KEM_SHARED_SECRET_LENGTH));
  }
}
