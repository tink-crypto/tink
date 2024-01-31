// Copyright 2022 Google LLC
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

import com.google.common.io.Files;
import com.google.common.truth.Expect;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.hybrid.HpkePrivateKey;
import com.google.crypto.tink.hybrid.HpkePublicKey;
import com.google.crypto.tink.testing.HpkeTestId;
import com.google.crypto.tink.testing.HpkeTestSetup;
import com.google.crypto.tink.testing.HpkeTestUtil;
import com.google.crypto.tink.testing.HpkeTestVector;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Map;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link HpkeKemKeyFactory}. */
@RunWith(Theories.class)
public final class HpkeKemKeyFactoryTest {
  private static Map<HpkeTestId, HpkeTestVector> testVectors;
  @Rule public final Expect expect = Expect.create();

  @BeforeClass
  public static void setUpTestVectors() throws IOException {
    String path = "testdata/testvectors/hpke_boringssl.json";
    if (TestUtil.isAndroid()) {
      path = "/sdcard/googletest/test_runfiles/google3/" + path; // Special prefix for Android.
    }
    testVectors = HpkeTestUtil.parseTestVectors(Files.newReader(new File(path), UTF_8));
  }

  private HpkePrivateKey createHpkePrivateKey(byte[] kemIdBytes, HpkeParameters.KemId kemId)
      throws GeneralSecurityException {
    HpkeTestId testId =
        new HpkeTestId(
            HpkeUtil.BASE_MODE,
            kemIdBytes,
            HpkeUtil.HKDF_SHA256_KDF_ID,
            HpkeUtil.CHACHA20_POLY1305_AEAD_ID);
    HpkeTestSetup testSetup = testVectors.get(testId).getTestSetup();
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(kemId)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.CHACHA20_POLY1305)
            .build();
    return createHpkePrivateKeyFromBytes(
        testSetup.recipientPrivateKey, testSetup.recipientPublicKey, parameters);
  }

  private HpkePrivateKey createHpkePrivateKeyFromBytes(
      byte[] privateKey, byte[] publicKey, HpkeParameters parameters)
      throws GeneralSecurityException {
    return HpkePrivateKey.create(
        HpkePublicKey.create(parameters, Bytes.copyFrom(publicKey), /* idRequirement= */ null),
        SecretBytes.copyFrom(privateKey, InsecureSecretKeyAccess.get()));
  }

  private static class KemTestCase {
    final byte[] kemIdBytes;
    final HpkeParameters.KemId kemId;

    KemTestCase(byte[] kemIdBytes, HpkeParameters.KemId kemId) {
      this.kemIdBytes = kemIdBytes;
      this.kemId = kemId;
    }
  }

  @DataPoints("kems")
  public static final KemTestCase[] KEMS =
      new KemTestCase[] {
        new KemTestCase(
            HpkeUtil.X25519_HKDF_SHA256_KEM_ID, HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256),
        new KemTestCase(
            HpkeUtil.P256_HKDF_SHA256_KEM_ID, HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256),
        new KemTestCase(
            HpkeUtil.P521_HKDF_SHA512_KEM_ID, HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512),
      };

  @Theory
  public void createKemPrivateKey_fromValidHpkePrivateKey_succeeds(
      @FromDataPoints("kems") KemTestCase testCase) throws GeneralSecurityException {
    HpkePrivateKey hpkePrivateKey = createHpkePrivateKey(testCase.kemIdBytes, testCase.kemId);
    HpkeKemPrivateKey hpkeKemPrivateKey = HpkeKemKeyFactory.createPrivate(hpkePrivateKey);

    expect
        .that(hpkeKemPrivateKey.getSerializedPrivate().toByteArray())
        .isEqualTo(hpkePrivateKey.getPrivateKeyBytes().toByteArray(InsecureSecretKeyAccess.get()));
    expect
        .that(hpkeKemPrivateKey.getSerializedPublic().toByteArray())
        .isEqualTo(hpkePrivateKey.getPublicKey().getPublicKeyBytes().toByteArray());
  }

}
