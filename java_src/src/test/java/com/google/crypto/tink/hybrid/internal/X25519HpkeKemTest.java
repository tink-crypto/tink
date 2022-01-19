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
import com.google.crypto.tink.testing.HpkeTestId;
import com.google.crypto.tink.testing.HpkeTestSetup;
import com.google.crypto.tink.testing.HpkeTestUtil;
import com.google.crypto.tink.testing.HpkeTestVector;
import com.google.crypto.tink.testing.TestUtil;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Map;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link X25519HpkeKem}. */
@RunWith(JUnit4.class)
public final class X25519HpkeKemTest {
  private static final byte[] EXPORT_ONLY_AEAD_ID = HpkeUtil.intToByteArray(2, 0xffff);
  private static final String MAC_ALGORITHM = "HmacSha256";

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

  private HpkeTestId getDefaultTestId() {
    return new HpkeTestId(
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.AES_128_GCM_AEAD_ID);
  }

  private void encapsulate(byte[] mode, byte[] kemId, byte[] kdfId, byte[] aeadId)
      throws GeneralSecurityException {
    HpkeTestId testId = new HpkeTestId(mode, kemId, kdfId, aeadId);
    HpkeTestSetup testSetup = testVectors.get(testId).getTestSetup();

    X25519HpkeKem kem = new X25519HpkeKem(new HkdfHpkeKdf(MAC_ALGORITHM));
    HpkeKemEncapOutput result =
        kem.encapsulate(testSetup.recipientPublicKey, testSetup.senderPrivateKey);
    expect.that(result.getSharedSecret()).isEqualTo(testSetup.sharedSecret);
    expect.that(result.getEncapsulatedKey()).isEqualTo(testSetup.encapsulatedKey);
  }

  private void decapsulate(byte[] mode, byte[] kemId, byte[] kdfId, byte[] aeadId)
      throws GeneralSecurityException {
    HpkeTestId testId = new HpkeTestId(mode, kemId, kdfId, aeadId);
    HpkeTestSetup testSetup = testVectors.get(testId).getTestSetup();

    X25519HpkeKem kem = new X25519HpkeKem(new HkdfHpkeKdf(MAC_ALGORITHM));
    byte[] result = kem.decapsulate(testSetup.encapsulatedKey, testSetup.recipientPrivateKey);
    expect.that(result).isEqualTo(testSetup.sharedSecret);
  }

  @Test
  public void encapsulate_succeedsWithX25519HkdfSha256Aes128Gcm() throws GeneralSecurityException {
    encapsulate(
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.AES_128_GCM_AEAD_ID);
  }

  @Test
  public void encapsulate_succeedsWithX25519HkdfSha256Aes256Gcm() throws GeneralSecurityException {
    encapsulate(
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.AES_256_GCM_AEAD_ID);
  }

  @Test
  public void encapsulate_succeedsWithX25519HkdfSha256ChaChaPoly1305()
      throws GeneralSecurityException {
    encapsulate(
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.CHACHA20_POLY1305_AEAD_ID);
  }

  @Test
  public void encapsulate_succeedsWithX25519HkdfSha256ExportOnlyAead()
      throws GeneralSecurityException {
    encapsulate(
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        EXPORT_ONLY_AEAD_ID);
  }

  @Test
  public void encapsulate_failsWithInvalidMacAlgorithm() {
    X25519HpkeKem kem = new X25519HpkeKem(new HkdfHpkeKdf("BadMac"));
    HpkeTestSetup testSetup = testVectors.get(getDefaultTestId()).getTestSetup();
    byte[] validRecipientPublicKey = testSetup.recipientPublicKey;
    assertThrows(NoSuchAlgorithmException.class, () -> kem.encapsulate(validRecipientPublicKey));
  }

  @Test
  public void encapsulate_failsWithInvalidRecipientPublicKey() {
    X25519HpkeKem kem = new X25519HpkeKem(new HkdfHpkeKdf(MAC_ALGORITHM));
    HpkeTestSetup testSetup = testVectors.get(getDefaultTestId()).getTestSetup();
    byte[] invalidRecipientPublicKey =
        Arrays.copyOf(testSetup.recipientPublicKey, testSetup.recipientPublicKey.length + 2);
    assertThrows(InvalidKeyException.class, () -> kem.encapsulate(invalidRecipientPublicKey));
  }

  @Test
  public void decapsulate_succeedsWithX25519HkdfSha256Aes128Gcm() throws GeneralSecurityException {
    decapsulate(
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.AES_128_GCM_AEAD_ID);
  }

  @Test
  public void decapsulate_succeedsWithX25519HkdfSha256Aes256Gcm() throws GeneralSecurityException {
    decapsulate(
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.AES_256_GCM_AEAD_ID);
  }

  @Test
  public void decapsulate_succeedsWithX25519HkdfSha256ChaChaPoly1305()
      throws GeneralSecurityException {
    decapsulate(
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.CHACHA20_POLY1305_AEAD_ID);
  }

  @Test
  public void decapsulate_succeedsWithX25519HkdfSha256ExportOnlyAead()
      throws GeneralSecurityException {
    decapsulate(
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        EXPORT_ONLY_AEAD_ID);
  }

  @Test
  public void decapsulate_failsWithInvalidMacAlgorithm() {
    X25519HpkeKem kem = new X25519HpkeKem(new HkdfHpkeKdf("BadMac"));
    HpkeTestSetup testSetup = testVectors.get(getDefaultTestId()).getTestSetup();
    byte[] validEncapsulatedKey = testSetup.encapsulatedKey;
    byte[] validRecipientPrivateKey = testSetup.recipientPrivateKey;
    assertThrows(
        NoSuchAlgorithmException.class,
        () -> kem.decapsulate(validEncapsulatedKey, validRecipientPrivateKey));
  }

  @Test
  public void decapsulate_failsWithInvalidEncapsulatedPublicKey() {
    X25519HpkeKem kem = new X25519HpkeKem(new HkdfHpkeKdf(MAC_ALGORITHM));
    HpkeTestSetup testSetup = testVectors.get(getDefaultTestId()).getTestSetup();
    byte[] invalidEncapsulatedKey =
        Arrays.copyOf(testSetup.encapsulatedKey, testSetup.encapsulatedKey.length + 2);
    byte[] validRecipientPrivateKey = testSetup.recipientPrivateKey;
    assertThrows(
        InvalidKeyException.class,
        () -> kem.decapsulate(invalidEncapsulatedKey, validRecipientPrivateKey));
  }

  @Test
  public void decapsulate_failsWithInvalidRecipientPrivateKey() {
    X25519HpkeKem kem = new X25519HpkeKem(new HkdfHpkeKdf(MAC_ALGORITHM));
    HpkeTestSetup testSetup = testVectors.get(getDefaultTestId()).getTestSetup();
    byte[] validEncapsulatedKey = testSetup.encapsulatedKey;
    byte[] invalidRecipientPrivateKey =
        Arrays.copyOf(testSetup.recipientPrivateKey, testSetup.recipientPrivateKey.length + 2);
    assertThrows(
        InvalidKeyException.class,
        () -> kem.decapsulate(validEncapsulatedKey, invalidRecipientPrivateKey));
  }

  @Test
  public void getKemId_succeeds() throws GeneralSecurityException {
    X25519HpkeKem kem = new X25519HpkeKem(new HkdfHpkeKdf(MAC_ALGORITHM));
    expect.that(kem.getKemId()).isEqualTo(HpkeUtil.X25519_HKDF_SHA256_KEM_ID);
  }

  @Test
  public void getKemId_failsWithInvalidMacAlgorithm() {
    X25519HpkeKem kem = new X25519HpkeKem(new HkdfHpkeKdf("BadMac"));
    assertThrows(GeneralSecurityException.class, kem::getKemId);
  }
}
