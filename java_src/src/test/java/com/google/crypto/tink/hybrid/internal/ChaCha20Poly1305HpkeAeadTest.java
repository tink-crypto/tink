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
import com.google.common.truth.Expect;
import com.google.crypto.tink.testing.HpkeTestEncryption;
import com.google.crypto.tink.testing.HpkeTestId;
import com.google.crypto.tink.testing.HpkeTestSetup;
import com.google.crypto.tink.testing.HpkeTestUtil;
import com.google.crypto.tink.testing.HpkeTestVector;
import com.google.crypto.tink.testing.TestUtil;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.List;
import java.util.Map;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link ChaCha20Poly1305HpkeAead}. */
@RunWith(JUnit4.class)
public final class ChaCha20Poly1305HpkeAeadTest {
  private static Map<HpkeTestId, HpkeTestVector> testVectors;

  @Rule public final Expect expect = Expect.create();

  @BeforeClass
  public static void setUpTestVectors() throws IOException {
    String path = "testdata/testvectors/hpke_boringssl.json";
    if (TestUtil.isAndroid()) {
      path = "/sdcard/googletest/test_runfiles/google3/" + path;  // Special prefix for Android.
    }
    testVectors = HpkeTestUtil.parseTestVectors(Files.newReader(new File(path), UTF_8));
  }

  private HpkeTestVector getTestVector(byte[] mode, byte[] kemId, byte[] kdfId, byte[] aeadId) {
    HpkeTestId testId = new HpkeTestId(mode, kemId, kdfId, aeadId);
    return testVectors.get(testId);
  }

  private void testSealAndOpen(
      ChaCha20Poly1305HpkeAead aead, byte[] mode, byte[] kemId, byte[] kdfId, byte[] aeadId)
      throws GeneralSecurityException {
    HpkeTestVector testVector = getTestVector(mode, kemId, kdfId, aeadId);
    HpkeTestSetup testSetup = testVector.getTestSetup();
    List<HpkeTestEncryption> encryptions = testVector.getEncryptions();
    for (HpkeTestEncryption encryption : encryptions) {
      byte[] ciphertext =
          aead.seal(
              testSetup.key, encryption.nonce, encryption.plaintext, encryption.associatedData);
      byte[] plaintext =
          aead.open(
              testSetup.key, encryption.nonce, encryption.ciphertext, encryption.associatedData);
      expect.that(ciphertext).isEqualTo(encryption.ciphertext);
      expect.that(plaintext).isEqualTo(encryption.plaintext);
    }
  }

  @Test
  public void sealAndOpen() throws GeneralSecurityException {
    ChaCha20Poly1305HpkeAead aead = new ChaCha20Poly1305HpkeAead();
    testSealAndOpen(
        aead,
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.CHACHA20_POLY1305_AEAD_ID);
  }

  @Test
  public void seal_wrongKeyLength() throws GeneralSecurityException {
    ChaCha20Poly1305HpkeAead aead = new ChaCha20Poly1305HpkeAead();
    HpkeTestVector testVector =
        getTestVector(
            HpkeUtil.BASE_MODE,
            HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
            HpkeUtil.HKDF_SHA256_KDF_ID,
            HpkeUtil.AES_128_GCM_AEAD_ID); // 16-byte keys incompatible with above 'aead'.
    HpkeTestSetup setup = testVector.getTestSetup();
    HpkeTestEncryption encryption = testVector.getEncryptions().get(0);
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () ->
            aead.seal(
                setup.key, encryption.nonce, encryption.plaintext, encryption.associatedData));
  }

  @Test
  public void open_wrongKeyLength() throws GeneralSecurityException {
    ChaCha20Poly1305HpkeAead aead = new ChaCha20Poly1305HpkeAead();
    HpkeTestVector testVector =
        getTestVector(
            HpkeUtil.BASE_MODE,
            HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
            HpkeUtil.HKDF_SHA256_KDF_ID,
            HpkeUtil.AES_128_GCM_AEAD_ID); // 16-byte keys incompatible with above 'aead'.
    HpkeTestSetup setup = testVector.getTestSetup();
    HpkeTestEncryption encryption = testVector.getEncryptions().get(0);
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () ->
            aead.open(
                setup.key, encryption.nonce, encryption.ciphertext, encryption.associatedData));
  }
}
