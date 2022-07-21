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
import static org.junit.Assert.assertThrows;

import com.google.common.io.Files;
import com.google.common.truth.Expect;
import com.google.crypto.tink.proto.HpkeKem;
import com.google.crypto.tink.proto.HpkeParams;
import com.google.crypto.tink.proto.HpkePrivateKey;
import com.google.crypto.tink.proto.HpkePublicKey;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.testing.HpkeTestId;
import com.google.crypto.tink.testing.HpkeTestSetup;
import com.google.crypto.tink.testing.HpkeTestUtil;
import com.google.crypto.tink.testing.HpkeTestVector;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ByteString;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Map;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
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

  private HpkePrivateKey createHpkePrivateKey(byte[] kemId, byte[] kdfId, HpkeKem hpkeKem) {
    HpkeTestId testId =
        new HpkeTestId(HpkeUtil.BASE_MODE, kemId, kdfId, HpkeUtil.AES_128_GCM_AEAD_ID);
    HpkeTestSetup testSetup = testVectors.get(testId).getTestSetup();
    return createHpkePrivateKeyFromBytes(
        testSetup.recipientPrivateKey, testSetup.recipientPublicKey, hpkeKem);
  }

  private HpkePrivateKey createHpkePrivateKeyFromBytes(
      byte[] privateKey, byte[] publicKey, HpkeKem hpkeKem) {
    return HpkePrivateKey.newBuilder()
        .setPrivateKey(ByteString.copyFrom(privateKey))
        .setPublicKey(
            HpkePublicKey.newBuilder()
                .setPublicKey(ByteString.copyFrom(publicKey))
                .setParams(HpkeParams.newBuilder().setKem(hpkeKem).build()))
        .build();
  }

  private static final class HpkeKemKeyParams {
    final byte[] kemId;
    final byte[] kdfId;
    final HpkeKem hpkeKem;

    HpkeKemKeyParams(byte[] kemId, byte[] kdfId, HpkeKem hpkeKem) {
      this.kemId = kemId;
      this.kdfId = kdfId;
      this.hpkeKem = hpkeKem;
    }
  }

  @DataPoints("hpkeKemKeyParams")
  public static final HpkeKemKeyParams[] HPKE_KEM_KEY_PARAMS =
      new HpkeKemKeyParams[] {
        new HpkeKemKeyParams(
            HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
            HpkeUtil.HKDF_SHA256_KDF_ID,
            HpkeKem.DHKEM_X25519_HKDF_SHA256),
        new HpkeKemKeyParams(
            HpkeUtil.P256_HKDF_SHA256_KEM_ID,
            HpkeUtil.HKDF_SHA256_KDF_ID,
            HpkeKem.DHKEM_P256_HKDF_SHA256),
        new HpkeKemKeyParams(
            HpkeUtil.P521_HKDF_SHA512_KEM_ID,
            HpkeUtil.HKDF_SHA512_KDF_ID,
            HpkeKem.DHKEM_P521_HKDF_SHA512),
      };

  @Theory
  public void createKemPrivateKey_fromValidHpkePrivateKey_succeeds(
      @FromDataPoints("hpkeKemKeyParams") HpkeKemKeyParams hpkeKemParams)
      throws GeneralSecurityException {
    HpkePrivateKey hpkePrivateKey =
        createHpkePrivateKey(hpkeKemParams.kemId, hpkeKemParams.kdfId, hpkeKemParams.hpkeKem);
    HpkeKemPrivateKey hpkeKemPrivateKey = HpkeKemKeyFactory.createPrivate(hpkePrivateKey);
    expect
        .that(hpkeKemPrivateKey.getSerializedPrivate().toByteArray())
        .isEqualTo(hpkePrivateKey.getPrivateKey().toByteArray());
    expect
        .that(hpkeKemPrivateKey.getSerializedPublic().toByteArray())
        .isEqualTo(hpkePrivateKey.getPublicKey().getPublicKey().toByteArray());
  }

  @Test
  public void createKemPrivateKey_fromInvalidPublicKey_fails() throws GeneralSecurityException {
    HpkePrivateKey hpkePrivateKey =
        createHpkePrivateKeyFromBytes(
            // Manually generated ECC Key with truncated public key
            Hex.decode("5b15c67a05a86a4a43c94db6f38a40c82930d417bef76ad774af1b28f93db061"),
            Hex.decode("45965373844c9176c1ff1d0650703104"),
            HpkeKem.DHKEM_P256_HKDF_SHA256);
    assertThrows(
        GeneralSecurityException.class, () -> HpkeKemKeyFactory.createPrivate(hpkePrivateKey));
  }

  @Test
  public void createKemPrivateKey_fromInvalidHpkeKemParams_fails() throws GeneralSecurityException {
    HpkePrivateKey hpkePrivateKey =
        createHpkePrivateKey(
            HpkeUtil.X25519_HKDF_SHA256_KEM_ID, HpkeUtil.HKDF_SHA256_KDF_ID, HpkeKem.KEM_UNKNOWN);
    assertThrows(
        GeneralSecurityException.class, () -> HpkeKemKeyFactory.createPrivate(hpkePrivateKey));
  }
}
