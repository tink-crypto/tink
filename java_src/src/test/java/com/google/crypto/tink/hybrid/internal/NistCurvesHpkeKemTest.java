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
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EllipticCurves.PointFormatType;
import com.google.crypto.tink.testing.HpkeTestId;
import com.google.crypto.tink.testing.HpkeTestSetup;
import com.google.crypto.tink.testing.HpkeTestUtil;
import com.google.crypto.tink.testing.HpkeTestVector;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ByteString;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Map;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link NistCurvesHpkeKem}. */
@RunWith(Theories.class)
public final class NistCurvesHpkeKemTest {
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

  private static final class HpkeKemParams {
    final byte[] kemId;
    final byte[] hkdfId;
    final byte[] aeadId;

    HpkeKemParams(byte[] kemId, byte[] hkdfId, byte[] aeadId) {
      this.kemId = kemId;
      this.hkdfId = hkdfId;
      this.aeadId = aeadId;
    }
  }

  @DataPoints("hpkeKemParams")
  public static final HpkeKemParams[] HPKE_KEM_PARAMS =
      new HpkeKemParams[] {
        new HpkeKemParams(
            HpkeUtil.P256_HKDF_SHA256_KEM_ID,
            HpkeUtil.HKDF_SHA256_KDF_ID,
            HpkeUtil.AES_128_GCM_AEAD_ID),
        new HpkeKemParams(
            HpkeUtil.P256_HKDF_SHA256_KEM_ID,
            HpkeUtil.HKDF_SHA256_KDF_ID,
            HpkeUtil.AES_256_GCM_AEAD_ID),
        new HpkeKemParams(
            HpkeUtil.P256_HKDF_SHA256_KEM_ID,
            HpkeUtil.HKDF_SHA256_KDF_ID,
            HpkeUtil.CHACHA20_POLY1305_AEAD_ID),
        new HpkeKemParams(
            HpkeUtil.P521_HKDF_SHA512_KEM_ID,
            HpkeUtil.HKDF_SHA512_KDF_ID,
            HpkeUtil.AES_128_GCM_AEAD_ID),
        new HpkeKemParams(
            HpkeUtil.P521_HKDF_SHA512_KEM_ID,
            HpkeUtil.HKDF_SHA512_KDF_ID,
            HpkeUtil.AES_256_GCM_AEAD_ID),
        new HpkeKemParams(
            HpkeUtil.P521_HKDF_SHA512_KEM_ID,
            HpkeUtil.HKDF_SHA512_KDF_ID,
            HpkeUtil.CHACHA20_POLY1305_AEAD_ID),
        // TODO(b/235861932): add manual test vectors for P384.
      };

  private EllipticCurves.CurveType curveTypeFromKemId(byte[] kemId)
      throws GeneralSecurityException {
    if (Arrays.equals(kemId, HpkeUtil.P256_HKDF_SHA256_KEM_ID)) {
      return EllipticCurves.CurveType.NIST_P256;
    }
    if (Arrays.equals(kemId, HpkeUtil.P384_HKDF_SHA384_KEM_ID)) {
      return EllipticCurves.CurveType.NIST_P384;
    }
    if (Arrays.equals(kemId, HpkeUtil.P521_HKDF_SHA512_KEM_ID)) {
      return EllipticCurves.CurveType.NIST_P521;
    }
    throw new GeneralSecurityException("invalid NIST kem id");
  }

  private HpkeKem kemIdToKemProtoParam(byte[] kemId) throws GeneralSecurityException {
    if (Arrays.equals(kemId, HpkeUtil.P256_HKDF_SHA256_KEM_ID)) {
      return HpkeKem.DHKEM_P256_HKDF_SHA256;
    }
    if (Arrays.equals(kemId, HpkeUtil.P384_HKDF_SHA384_KEM_ID)) {
      return HpkeKem.DHKEM_P384_HKDF_SHA384;
    }
    if (Arrays.equals(kemId, HpkeUtil.P521_HKDF_SHA512_KEM_ID)) {
      return HpkeKem.DHKEM_P521_HKDF_SHA512;
    }
    throw new GeneralSecurityException("invalid NIST kem id");
  }

  @Theory
  public void encapsulate_succeeds(@FromDataPoints("hpkeKemParams") HpkeKemParams hpkeNistKemParams)
      throws GeneralSecurityException {
    HpkeTestId testId =
        new HpkeTestId(
            HpkeUtil.BASE_MODE,
            hpkeNistKemParams.kemId,
            hpkeNistKemParams.hkdfId,
            hpkeNistKemParams.aeadId);
    HpkeTestSetup testSetup = testVectors.get(testId).getTestSetup();
    EllipticCurves.CurveType curve = curveTypeFromKemId(hpkeNistKemParams.kemId);
    ECPrivateKey privateKey = EllipticCurves.getEcPrivateKey(curve, testSetup.senderPrivateKey);
    ECPublicKey publicKey =
        EllipticCurves.getEcPublicKey(
            curve, PointFormatType.UNCOMPRESSED, testSetup.senderPublicKey);
    NistCurvesHpkeKem kem = NistCurvesHpkeKem.fromCurve(curve);
    HpkeKemEncapOutput result =
        kem.encapsulate(testSetup.recipientPublicKey, new KeyPair(publicKey, privateKey));
    expect.that(result.getSharedSecret()).isEqualTo(testSetup.sharedSecret);
    expect.that(result.getEncapsulatedKey()).isEqualTo(testSetup.encapsulatedKey);
  }

  @Theory
  public void decapsulate_succeeds(@FromDataPoints("hpkeKemParams") HpkeKemParams hpkeNistKemParams)
      throws GeneralSecurityException {
    HpkeTestId testId =
        new HpkeTestId(
            HpkeUtil.BASE_MODE,
            hpkeNistKemParams.kemId,
            hpkeNistKemParams.hkdfId,
            hpkeNistKemParams.aeadId);
    HpkeTestSetup testSetup = testVectors.get(testId).getTestSetup();
    HpkeKemPrivateKey recipientKeyPair =
        HpkeKemKeyFactory.createPrivate(
            HpkePrivateKey.newBuilder()
                .setPrivateKey(ByteString.copyFrom(testSetup.recipientPrivateKey))
                .setPublicKey(
                    HpkePublicKey.newBuilder()
                        .setPublicKey(ByteString.copyFrom(testSetup.recipientPublicKey))
                        .setParams(
                            HpkeParams.newBuilder()
                                .setKem(kemIdToKemProtoParam(hpkeNistKemParams.kemId))
                                .build())
                        .build())
                .build());
    NistCurvesHpkeKem kem =
        NistCurvesHpkeKem.fromCurve(curveTypeFromKemId(hpkeNistKemParams.kemId));
    byte[] result = kem.decapsulate(testSetup.encapsulatedKey, recipientKeyPair);
    expect.that(result).isEqualTo(testSetup.sharedSecret);
  }

  @Theory
  public void encapsulate_failsWithInvalidRecipientPublicKey(
      @FromDataPoints("hpkeKemParams") HpkeKemParams hpkeNistKemParams)
      throws GeneralSecurityException {
    HpkeTestId testId =
        new HpkeTestId(
            HpkeUtil.BASE_MODE,
            hpkeNistKemParams.kemId,
            hpkeNistKemParams.hkdfId,
            hpkeNistKemParams.aeadId);
    HpkeTestSetup testSetup = testVectors.get(testId).getTestSetup();
    NistCurvesHpkeKem kem =
        NistCurvesHpkeKem.fromCurve(curveTypeFromKemId(hpkeNistKemParams.kemId));
    byte[] invalidRecipientPublicKey =
        Arrays.copyOf(testSetup.recipientPublicKey, testSetup.recipientPublicKey.length + 2);
    assertThrows(GeneralSecurityException.class, () -> kem.encapsulate(invalidRecipientPublicKey));
  }

  @Theory
  public void decapsulate_failsWithInvalidEncapsulatedPublicKey(
      @FromDataPoints("hpkeKemParams") HpkeKemParams hpkeNistKemParams)
      throws GeneralSecurityException {
    HpkeTestId testId =
        new HpkeTestId(
            HpkeUtil.BASE_MODE,
            hpkeNistKemParams.kemId,
            hpkeNistKemParams.hkdfId,
            hpkeNistKemParams.aeadId);
    HpkeTestSetup testSetup = testVectors.get(testId).getTestSetup();
    byte[] invalidEncapsulatedKey =
        Arrays.copyOf(testSetup.encapsulatedKey, testSetup.encapsulatedKey.length + 2);
    EllipticCurves.CurveType curve = curveTypeFromKemId(hpkeNistKemParams.kemId);
    NistCurvesHpkeKem kem = NistCurvesHpkeKem.fromCurve(curve);
    HpkeKemPrivateKey validRecipientPrivateKey =
        NistCurvesHpkeKemPrivateKey.fromBytes(
            testSetup.recipientPrivateKey, testSetup.recipientPublicKey, curve);
    assertThrows(
        GeneralSecurityException.class,
        () -> kem.decapsulate(invalidEncapsulatedKey, validRecipientPrivateKey));
  }
}
