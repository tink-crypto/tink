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
import com.google.crypto.tink.hybrid.HpkeParameters;
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

  private static final class KemTestCase {
    final byte[] bytesId;
    final com.google.crypto.tink.proto.HpkeKem protoId;
    final HpkeParameters.KemId kemId;
    final Class<? extends HpkeKem> kemClass;

    KemTestCase(
        byte[] bytesId,
        com.google.crypto.tink.proto.HpkeKem protoId,
        HpkeParameters.KemId kemId,
        Class<? extends HpkeKem> kemClass) {
      this.bytesId = bytesId;
      this.protoId = protoId;
      this.kemId = kemId;
      this.kemClass = kemClass;
    }
  }

  private static final class KdfTestCase {
    final byte[] bytesId;
    final com.google.crypto.tink.proto.HpkeKdf protoId;
    final HpkeParameters.KdfId kdfId;
    final Class<? extends HpkeKdf> kdfClass;

    KdfTestCase(
        byte[] bytesId,
        com.google.crypto.tink.proto.HpkeKdf protoId,
        HpkeParameters.KdfId kdfId,
        Class<? extends HpkeKdf> kdfClass) {
      this.bytesId = bytesId;
      this.protoId = protoId;
      this.kdfId = kdfId;
      this.kdfClass = kdfClass;
    }
  }

  private static final class AeadTestCase {
    final byte[] bytesId;
    final com.google.crypto.tink.proto.HpkeAead protoId;
    final HpkeParameters.AeadId aeadId;
    final Class<? extends HpkeAead> aeadClass;
    final int keyLength;
    final int nonceLength;

    AeadTestCase(
        byte[] bytesId,
        com.google.crypto.tink.proto.HpkeAead protoId,
        HpkeParameters.AeadId aeadId,
        Class<? extends HpkeAead> aeadClass,
        int keyLength,
        int nonceLength) {
      this.bytesId = bytesId;
      this.protoId = protoId;
      this.aeadId = aeadId;
      this.aeadClass = aeadClass;
      this.keyLength = keyLength;
      this.nonceLength = nonceLength;
    }
  }

  @DataPoints("kems")
  public static final KemTestCase[] KEMS =
      new KemTestCase[] {
        new KemTestCase(
            HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
            com.google.crypto.tink.proto.HpkeKem.DHKEM_X25519_HKDF_SHA256,
            HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256,
            X25519HpkeKem.class),
        new KemTestCase(
            HpkeUtil.P256_HKDF_SHA256_KEM_ID,
            com.google.crypto.tink.proto.HpkeKem.DHKEM_P256_HKDF_SHA256,
            HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256,
            NistCurvesHpkeKem.class),
        new KemTestCase(
            HpkeUtil.P384_HKDF_SHA384_KEM_ID,
            com.google.crypto.tink.proto.HpkeKem.DHKEM_P384_HKDF_SHA384,
            HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384,
            NistCurvesHpkeKem.class),
        new KemTestCase(
            HpkeUtil.P521_HKDF_SHA512_KEM_ID,
            com.google.crypto.tink.proto.HpkeKem.DHKEM_P521_HKDF_SHA512,
            HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512,
            NistCurvesHpkeKem.class)
      };

  @DataPoints("kdfs")
  public static final KdfTestCase[] KDFS =
      new KdfTestCase[] {
        new KdfTestCase(
            HpkeUtil.HKDF_SHA256_KDF_ID,
            com.google.crypto.tink.proto.HpkeKdf.HKDF_SHA256,
            HpkeParameters.KdfId.HKDF_SHA256,
            HkdfHpkeKdf.class),
        new KdfTestCase(
            HpkeUtil.HKDF_SHA384_KDF_ID,
            com.google.crypto.tink.proto.HpkeKdf.HKDF_SHA384,
            HpkeParameters.KdfId.HKDF_SHA384,
            HkdfHpkeKdf.class),
        new KdfTestCase(
            HpkeUtil.HKDF_SHA512_KDF_ID,
            com.google.crypto.tink.proto.HpkeKdf.HKDF_SHA512,
            HpkeParameters.KdfId.HKDF_SHA512,
            HkdfHpkeKdf.class)
      };

  @DataPoints("aeads")
  public static final AeadTestCase[] AEADS =
      new AeadTestCase[] {
        new AeadTestCase(
            HpkeUtil.AES_128_GCM_AEAD_ID,
            com.google.crypto.tink.proto.HpkeAead.AES_128_GCM,
            HpkeParameters.AeadId.AES_128_GCM,
            AesGcmHpkeAead.class,
            /* keyLength= */ 16,
            /* nonceLength= */ 12),
        new AeadTestCase(
            HpkeUtil.AES_256_GCM_AEAD_ID,
            com.google.crypto.tink.proto.HpkeAead.AES_256_GCM,
            HpkeParameters.AeadId.AES_256_GCM,
            AesGcmHpkeAead.class,
            /* keyLength= */ 32,
            /* nonceLength= */ 12),
        new AeadTestCase(
            HpkeUtil.CHACHA20_POLY1305_AEAD_ID,
            com.google.crypto.tink.proto.HpkeAead.CHACHA20_POLY1305,
            HpkeParameters.AeadId.CHACHA20_POLY1305,
            ChaCha20Poly1305HpkeAead.class,
            /* keyLength= */ 32,
            /* nonceLength= */ 12)
      };

  @Theory
  public void createKem_fromValidKemBytesId_succeeds(@FromDataPoints("kems") KemTestCase testCase)
      throws Exception {
    HpkeKem kem = HpkePrimitiveFactory.createKem(testCase.bytesId);

    expect.that(kem).isInstanceOf(testCase.kemClass);
    expect.that(kem.getKemId()).isEqualTo(testCase.bytesId);
  }

  @Test
  public void createKem_fromInvalidKemBytesId_fails() {
    byte[] invalidKemId = new byte[] {0, 0};

    assertThrows(
        IllegalArgumentException.class, () -> HpkePrimitiveFactory.createKem(invalidKemId));
  }

  @Theory
  public void createKem_fromValidKemId_succeeds(@FromDataPoints("kems") KemTestCase testCase)
      throws Exception {
    HpkeKem kem = HpkePrimitiveFactory.createKem(testCase.kemId);

    expect.that(kem).isInstanceOf(testCase.kemClass);
    expect.that(kem.getKemId()).isEqualTo(testCase.bytesId);
  }

  @Theory
  public void createKem_fromValidHpkeParams_succeeds(@FromDataPoints("kems") KemTestCase testCase)
      throws Exception {
    HpkeParams params = HpkeParams.newBuilder().setKem(testCase.protoId).build();
    HpkeKem kem = HpkePrimitiveFactory.createKem(params);

    expect.that(kem).isInstanceOf(testCase.kemClass);
    expect.that(kem.getKemId()).isEqualTo(testCase.bytesId);
  }

  @Test
  public void createKem_fromInvalidHpkeParams_fails() {
    HpkeParams params =
        HpkeParams.newBuilder().setKem(com.google.crypto.tink.proto.HpkeKem.KEM_UNKNOWN).build();

    assertThrows(IllegalArgumentException.class, () -> HpkePrimitiveFactory.createKem(params));
  }

  @Theory
  public void createKdf_fromValidKdfBytesId_succeeds(@FromDataPoints("kdfs") KdfTestCase testCase)
      throws Exception {
    HpkeKdf kdf = HpkePrimitiveFactory.createKdf(testCase.bytesId);

    expect.that(kdf).isInstanceOf(testCase.kdfClass);
    expect.that(kdf.getKdfId()).isEqualTo(testCase.bytesId);
  }

  @Test
  public void createKdf_fromInvalidKdfBytesId_fails() {
    byte[] invalidKdfId = new byte[] {0, 0};

    assertThrows(
        IllegalArgumentException.class, () -> HpkePrimitiveFactory.createKdf(invalidKdfId));
  }

  @Theory
  public void createKdf_fromValidKdfId_succeeds(@FromDataPoints("kdfs") KdfTestCase testCase)
      throws Exception {
    HpkeKdf kdf = HpkePrimitiveFactory.createKdf(testCase.kdfId);

    expect.that(kdf).isInstanceOf(testCase.kdfClass);
    expect.that(kdf.getKdfId()).isEqualTo(testCase.bytesId);
  }

  @Theory
  public void createKdf_fromValidHpkeParams_succeeds(@FromDataPoints("kdfs") KdfTestCase testCase)
      throws GeneralSecurityException {
    HpkeParams params = HpkeParams.newBuilder().setKdf(testCase.protoId).build();
    HpkeKdf kdf = HpkePrimitiveFactory.createKdf(params);

    expect.that(kdf).isInstanceOf(testCase.kdfClass);
    expect.that(kdf.getKdfId()).isEqualTo(testCase.bytesId);
  }

  @Test
  public void createKdf_fromInvalidHpkeParams_fails() {
    HpkeParams params =
        HpkeParams.newBuilder().setKdf(com.google.crypto.tink.proto.HpkeKdf.KDF_UNKNOWN).build();

    assertThrows(IllegalArgumentException.class, () -> HpkePrimitiveFactory.createKdf(params));
  }

  @Theory
  public void createAead_fromValidAeadBytesId_succeeds(
      @FromDataPoints("aeads") AeadTestCase testCase) throws Exception {
    HpkeAead aead = HpkePrimitiveFactory.createAead(testCase.bytesId);

    expect.that(aead).isInstanceOf(testCase.aeadClass);
    expect.that(aead.getAeadId()).isEqualTo(testCase.bytesId);
    expect.that(aead.getKeyLength()).isEqualTo(testCase.keyLength);
    expect.that(aead.getNonceLength()).isEqualTo(testCase.nonceLength);
  }

  @Test
  public void createAead_fromInvalidAeadBytesId_fails() {
    byte[] invalidAeadId = new byte[] {0, 0};

    assertThrows(
        IllegalArgumentException.class, () -> HpkePrimitiveFactory.createAead(invalidAeadId));
  }

  @Theory
  public void createAead_fromValidAeadId_succeeds(@FromDataPoints("aeads") AeadTestCase testCase)
      throws Exception {
    HpkeAead aead = HpkePrimitiveFactory.createAead(testCase.aeadId);

    expect.that(aead).isInstanceOf(testCase.aeadClass);
    expect.that(aead.getAeadId()).isEqualTo(testCase.bytesId);
    expect.that(aead.getKeyLength()).isEqualTo(testCase.keyLength);
    expect.that(aead.getNonceLength()).isEqualTo(testCase.nonceLength);
  }

  @Theory
  public void createAead_fromValidHpkeParams_succeeds(
      @FromDataPoints("aeads") AeadTestCase testCase) throws Exception {
    HpkeParams params = HpkeParams.newBuilder().setAead(testCase.protoId).build();
    HpkeAead aead = HpkePrimitiveFactory.createAead(params);

    expect.that(aead).isInstanceOf(testCase.aeadClass);
    expect.that(aead.getAeadId()).isEqualTo(testCase.bytesId);
    expect.that(aead.getKeyLength()).isEqualTo(testCase.keyLength);
    expect.that(aead.getNonceLength()).isEqualTo(testCase.nonceLength);
  }

  @Test
  public void createAead_fromInvalidHpkeParams_fails() {
    HpkeParams params =
        HpkeParams.newBuilder().setAead(com.google.crypto.tink.proto.HpkeAead.AEAD_UNKNOWN).build();

    assertThrows(IllegalArgumentException.class, () -> HpkePrimitiveFactory.createAead(params));
  }
}
