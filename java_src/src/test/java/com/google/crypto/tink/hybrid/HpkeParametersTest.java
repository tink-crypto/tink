// Copyright 2023 Google LLC
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

package com.google.crypto.tink.hybrid;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public final class HpkeParametersTest {

  @DataPoints("variants")
  public static final HpkeParameters.Variant[] VARIANTS =
      new HpkeParameters.Variant[] {
        HpkeParameters.Variant.TINK,
        HpkeParameters.Variant.CRUNCHY,
        HpkeParameters.Variant.NO_PREFIX,
      };

  @DataPoints("kemIds")
  public static final HpkeParameters.KemId[] KEM_IDS =
      new HpkeParameters.KemId[] {
        HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256,
        HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384,
        HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512,
        HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256,
      };

  @DataPoints("kdfIds")
  public static final HpkeParameters.KdfId[] KDF_IDS =
      new HpkeParameters.KdfId[] {
        HpkeParameters.KdfId.HKDF_SHA256,
        HpkeParameters.KdfId.HKDF_SHA384,
        HpkeParameters.KdfId.HKDF_SHA512,
      };

  @DataPoints("aeadIds")
  public static final HpkeParameters.AeadId[] AEAD_IDS =
      new HpkeParameters.AeadId[] {
        HpkeParameters.AeadId.AES_128_GCM,
        HpkeParameters.AeadId.AES_256_GCM,
        HpkeParameters.AeadId.CHACHA20_POLY1305,
      };

  @Theory
  public void buildParameters(
      @FromDataPoints("variants") HpkeParameters.Variant variant,
      @FromDataPoints("kemIds") HpkeParameters.KemId kemId,
      @FromDataPoints("kdfIds") HpkeParameters.KdfId kdfId,
      @FromDataPoints("aeadIds") HpkeParameters.AeadId aeadId)
      throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(variant)
            .setKemId(kemId)
            .setKdfId(kdfId)
            .setAeadId(aeadId)
            .build();

    assertThat(params.getVariant()).isEqualTo(variant);
    assertThat(params.getKemId()).isEqualTo(kemId);
    assertThat(params.getKdfId()).isEqualTo(kdfId);
    assertThat(params.getAeadId()).isEqualTo(aeadId);
  }

  @Theory
  public void buildParametersWithDefaultVariant(
      @FromDataPoints("kemIds") HpkeParameters.KemId kemId,
      @FromDataPoints("kdfIds") HpkeParameters.KdfId kdfId,
      @FromDataPoints("aeadIds") HpkeParameters.AeadId aeadId)
      throws Exception {
    HpkeParameters params =
        HpkeParameters.builder().setKemId(kemId).setKdfId(kdfId).setAeadId(aeadId).build();

    assertThat(params.getVariant()).isEqualTo(HpkeParameters.Variant.NO_PREFIX);
    assertThat(params.getKemId()).isEqualTo(kemId);
    assertThat(params.getKdfId()).isEqualTo(kdfId);
    assertThat(params.getAeadId()).isEqualTo(aeadId);
  }

  @Test
  public void buildParameters_failsWithoutKemId() throws Exception {
    HpkeParameters.Builder builder =
        HpkeParameters.builder()
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM);

    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void buildParameters_failsWithoutKdfId() throws Exception {
    HpkeParameters.Builder builder =
        HpkeParameters.builder()
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM);

    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void buildParameters_failsWithoutAeadId() throws Exception {
    HpkeParameters.Builder builder =
        HpkeParameters.builder()
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256);

    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void hasIdRequirement() throws Exception {
    HpkeParameters noPrefixParams =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    assertThat(noPrefixParams.hasIdRequirement()).isFalse();

    HpkeParameters tinkParams =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    assertThat(tinkParams.hasIdRequirement()).isTrue();

    HpkeParameters crunchyParams =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.CRUNCHY)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    assertThat(crunchyParams.hasIdRequirement()).isTrue();
  }

  @Test
  public void sameParamsAreEqual() throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();

    HpkeParameters duplicateParams =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();

    assertThat(params).isEqualTo(duplicateParams);
    assertThat(params.hashCode()).isEqualTo(duplicateParams.hashCode());
  }

  @Test
  public void differentVariantsAreNotEqual() throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();

    HpkeParameters differentVariant =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();

    assertThat(params).isNotEqualTo(differentVariant);
    assertThat(params.hashCode()).isNotEqualTo(differentVariant.hashCode());
  }

  @Test
  public void differentKemAreNotEqual() throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();

    HpkeParameters differentKem =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();

    assertThat(params).isNotEqualTo(differentKem);
    assertThat(params.hashCode()).isNotEqualTo(differentKem.hashCode());
  }

  @Test
  public void differentKdfsAreNotEqual() throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();

    HpkeParameters differentKdf =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA384)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();

    assertThat(params).isNotEqualTo(differentKdf);
    assertThat(params.hashCode()).isNotEqualTo(differentKdf.hashCode());
  }

  @Test
  public void differentAeadsAreNotEqual() throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();

    HpkeParameters differentAead =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build();

    assertThat(params).isNotEqualTo(differentAead);
    assertThat(params.hashCode()).isNotEqualTo(differentAead.hashCode());
  }
}
