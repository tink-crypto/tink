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

import static org.junit.Assert.assertThrows;

import com.google.common.truth.Expect;
import com.google.crypto.tink.proto.HpkeParams;
import java.security.GeneralSecurityException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link HpkePrimitiveFactory}. */
@RunWith(Theories.class)
public final class HpkePrimitiveFactoryTest {
  @Rule public final Expect expect = Expect.create();

  private static final class KdfParameter {
    final byte[] id;
    final com.google.crypto.tink.proto.HpkeKdf hpkeKdf;

    KdfParameter(byte[] id, com.google.crypto.tink.proto.HpkeKdf hpkeKdf) {
      this.id = id;
      this.hpkeKdf = hpkeKdf;
    }
  }

  @DataPoints("kdfParameters")
  public static final KdfParameter[] KDF_PARAMETERS =
      new KdfParameter[] {
        new KdfParameter(
            HpkeUtil.HKDF_SHA256_KDF_ID, com.google.crypto.tink.proto.HpkeKdf.HKDF_SHA256),
        new KdfParameter(
            HpkeUtil.HKDF_SHA384_KDF_ID, com.google.crypto.tink.proto.HpkeKdf.HKDF_SHA384),
        new KdfParameter(
            HpkeUtil.HKDF_SHA512_KDF_ID, com.google.crypto.tink.proto.HpkeKdf.HKDF_SHA512),
      };

  private static final class NistCurveKemParameter {
    final byte[] id;
    final com.google.crypto.tink.proto.HpkeKem hpkeKem;

    NistCurveKemParameter(byte[] id, com.google.crypto.tink.proto.HpkeKem hpkeKem) {
      this.id = id;
      this.hpkeKem = hpkeKem;
    }
  }

  @DataPoints("nistCurveKemParameters")
  public static final NistCurveKemParameter[] NIST_KEM_PARAMETERS =
      new NistCurveKemParameter[] {
        new NistCurveKemParameter(
            HpkeUtil.P256_HKDF_SHA256_KEM_ID,
            com.google.crypto.tink.proto.HpkeKem.DHKEM_P256_HKDF_SHA256),
        new NistCurveKemParameter(
            HpkeUtil.P384_HKDF_SHA384_KEM_ID,
            com.google.crypto.tink.proto.HpkeKem.DHKEM_P384_HKDF_SHA384),
        new NistCurveKemParameter(
            HpkeUtil.P521_HKDF_SHA512_KEM_ID,
            com.google.crypto.tink.proto.HpkeKem.DHKEM_P521_HKDF_SHA512),
      };

  @Test
  public void createKem_fromValidKemId_x25519HkdfSha256_succeeds() throws GeneralSecurityException {
    HpkeKem kem = HpkePrimitiveFactory.createKem(HpkeUtil.X25519_HKDF_SHA256_KEM_ID);
    expect.that(kem).isInstanceOf(X25519HpkeKem.class);
    expect.that(kem.getKemId()).isEqualTo(HpkeUtil.X25519_HKDF_SHA256_KEM_ID);
  }

  @Theory
  public void createKem_fromValidKemId_NistKem_succeeds(
      @FromDataPoints("nistCurveKemParameters") NistCurveKemParameter nistKemParameter)
      throws GeneralSecurityException {
    HpkeKem kem = HpkePrimitiveFactory.createKem(nistKemParameter.id);
    expect.that(kem).isInstanceOf(NistCurvesHpkeKem.class);
    expect.that(kem.getKemId()).isEqualTo(nistKemParameter.id);
  }

  @Test
  public void createKem_fromInvalidKemId_fails() {
    byte[] invalidKemId = new byte[] {0, 0};
    assertThrows(
        IllegalArgumentException.class, () -> HpkePrimitiveFactory.createKem(invalidKemId));
  }

  @Test
  public void createKem_fromValidHpkeParams_x25519HkdfSha256_succeeds()
      throws GeneralSecurityException {
    HpkeParams params =
        HpkeParams.newBuilder()
            .setKem(com.google.crypto.tink.proto.HpkeKem.DHKEM_X25519_HKDF_SHA256)
            .build();
    HpkeKem kem = HpkePrimitiveFactory.createKem(params);
    expect.that(kem).isInstanceOf(X25519HpkeKem.class);
    expect.that(kem.getKemId()).isEqualTo(HpkeUtil.X25519_HKDF_SHA256_KEM_ID);
  }

  @Theory
  public void createKem_fromValidHpkeParams_nistCurveKem_succeeds(
      @FromDataPoints("nistCurveKemParameters") NistCurveKemParameter nistKemParameter)
      throws GeneralSecurityException {
    HpkeParams params = HpkeParams.newBuilder().setKem(nistKemParameter.hpkeKem).build();
    HpkeKem kem = HpkePrimitiveFactory.createKem(params);
    expect.that(kem).isInstanceOf(NistCurvesHpkeKem.class);
    expect.that(kem.getKemId()).isEqualTo(nistKemParameter.id);
  }

  @Test
  public void createKem_fromInvalidHpkeParams_fails() {
    HpkeParams params =
        HpkeParams.newBuilder().setKem(com.google.crypto.tink.proto.HpkeKem.KEM_UNKNOWN).build();
    assertThrows(IllegalArgumentException.class, () -> HpkePrimitiveFactory.createKem(params));
  }

  @Theory
  public void createKdf_fromValidKdfId_succeeds(
      @FromDataPoints("kdfParameters") KdfParameter kdfParameter) throws GeneralSecurityException {
    HpkeKdf kdf = HpkePrimitiveFactory.createKdf(kdfParameter.id);
    expect.that(kdf).isInstanceOf(HkdfHpkeKdf.class);
    expect.that(kdf.getKdfId()).isEqualTo(kdfParameter.id);
  }

  @Test
  public void createKdf_fromInvalidKdfId_fails() {
    byte[] invalidKdfId = new byte[] {0, 0};
    assertThrows(
        IllegalArgumentException.class, () -> HpkePrimitiveFactory.createKdf(invalidKdfId));
  }

  @Theory
  public void createKdf_fromValidHpkeParams_succeeds(
      @FromDataPoints("kdfParameters") KdfParameter kdfParameter) throws GeneralSecurityException {
    HpkeParams params = HpkeParams.newBuilder().setKdf(kdfParameter.hpkeKdf).build();
    HpkeKdf kdf = HpkePrimitiveFactory.createKdf(params);
    expect.that(kdf).isInstanceOf(HkdfHpkeKdf.class);
    expect.that(kdf.getKdfId()).isEqualTo(kdfParameter.id);
  }

  @Test
  public void createKdf_fromInvalidHpkeParams_fails() {
    HpkeParams params =
        HpkeParams.newBuilder().setKdf(com.google.crypto.tink.proto.HpkeKdf.KDF_UNKNOWN).build();
    assertThrows(IllegalArgumentException.class, () -> HpkePrimitiveFactory.createKdf(params));
  }

  @Test
  public void createAead_fromValidAeadId_succeeds() throws GeneralSecurityException {
    HpkeAead aead = HpkePrimitiveFactory.createAead(HpkeUtil.AES_128_GCM_AEAD_ID);
    expect.that(aead).isInstanceOf(AesGcmHpkeAead.class);
    expect.that(aead.getAeadId()).isEqualTo(HpkeUtil.AES_128_GCM_AEAD_ID);
    expect.that(aead.getKeyLength()).isEqualTo(16);
    expect.that(aead.getNonceLength()).isEqualTo(12);
  }

  @Test
  public void createAead_fromInvalidAeadId_fails() {
    byte[] invalidAeadId = new byte[] {0, 0};
    assertThrows(
        IllegalArgumentException.class, () -> HpkePrimitiveFactory.createAead(invalidAeadId));
  }

  @Test
  public void createAead_fromValidHpkeParams_succeeds() throws GeneralSecurityException {
    HpkeParams params =
        HpkeParams.newBuilder().setAead(com.google.crypto.tink.proto.HpkeAead.AES_128_GCM).build();
    HpkeAead aead = HpkePrimitiveFactory.createAead(params);
    expect.that(aead).isInstanceOf(AesGcmHpkeAead.class);
    expect.that(aead.getAeadId()).isEqualTo(HpkeUtil.AES_128_GCM_AEAD_ID);
    expect.that(aead.getKeyLength()).isEqualTo(16);
    expect.that(aead.getNonceLength()).isEqualTo(12);
  }

  @Test
  public void createAead_fromInvalidHpkeParams_fails() {
    HpkeParams params =
        HpkeParams.newBuilder().setAead(com.google.crypto.tink.proto.HpkeAead.AEAD_UNKNOWN).build();
    assertThrows(IllegalArgumentException.class, () -> HpkePrimitiveFactory.createAead(params));
  }
}
