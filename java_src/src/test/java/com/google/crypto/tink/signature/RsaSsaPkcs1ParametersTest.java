// Copyright 2022 Google LLC
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

package com.google.crypto.tink.signature;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class RsaSsaPkcs1ParametersTest {

  @Test
  public void buildWithNoPrefixAndGetProperties() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters.getModulusSizeBits()).isEqualTo(2048);
    assertThat(parameters.getPublicExponent()).isEqualTo(RsaSsaPkcs1Parameters.F4);
    assertThat(parameters.getHashType()).isEqualTo(RsaSsaPkcs1Parameters.HashType.SHA256);
    assertThat(parameters.getVariant()).isEqualTo(RsaSsaPkcs1Parameters.Variant.NO_PREFIX);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void buildParametersWithoutSettingVariant_hasNoPrefix() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .build();
    assertThat(parameters.getVariant()).isEqualTo(RsaSsaPkcs1Parameters.Variant.NO_PREFIX);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void buildParametersWithoutExponent() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters.getPublicExponent()).isEqualTo(RsaSsaPkcs1Parameters.F4);
  }

  @Test
  public void buildParametersWithTinkPrefix() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.TINK)
            .build();
    assertThat(parameters.getVariant()).isEqualTo(RsaSsaPkcs1Parameters.Variant.TINK);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void buildParametersWithLegacyPrefix() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.LEGACY)
            .build();
    assertThat(parameters.getVariant()).isEqualTo(RsaSsaPkcs1Parameters.Variant.LEGACY);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void buildParametersWithCrunchyPrefix() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.CRUNCHY)
            .build();
    assertThat(parameters.getVariant()).isEqualTo(RsaSsaPkcs1Parameters.Variant.CRUNCHY);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void buildParametersWithLargeModulusSize() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(16789)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters.getModulusSizeBits()).isEqualTo(16789);
  }

  @Test
  public void buildParametersWithValidNonF4PublicExponentSet() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(BigInteger.valueOf(1234567))
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters.getPublicExponent()).isEqualTo(BigInteger.valueOf(1234567));
  }

  @Test
  public void buildParametersWithSmallPublicExponent_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(BigInteger.valueOf(3))
                .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
                .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void buildParametersWithEvenPublicExponent_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(BigInteger.valueOf(1234568))
                .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
                .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void buildParametersWithLargePublicExponent_works() throws Exception {
    BigInteger largeE = BigInteger.valueOf(100000000001L);
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(largeE)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters.getPublicExponent()).isEqualTo(largeE);
  }

  // Public exponents larger than 2^256 are rejected. See:
  // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf, B.3
  @Test
  public void buildParametersWithTooLargePublicExponent_fails() throws Exception {
    BigInteger tooLargeE = BigInteger.valueOf(2).pow(256).add(BigInteger.ONE);
    assertThat(tooLargeE.bitLength()).isEqualTo(257);
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(tooLargeE)
                .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
                .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void buildParametersWithSha384() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(3072)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA384)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters.getHashType()).isEqualTo(RsaSsaPkcs1Parameters.HashType.SHA384);
  }

  @Test
  public void buildParametersWithSha512() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA512)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters.getHashType()).isEqualTo(RsaSsaPkcs1Parameters.HashType.SHA512);
  }

  @Test
  public void buildWithoutSettingModulusSize_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPkcs1Parameters.builder()
                .setPublicExponent(RsaSsaPkcs1Parameters.F4)
                .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
                .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void buildWithoutSettingHashType_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(RsaSsaPkcs1Parameters.F4)
                .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void buildWithVariantSetToNull_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(RsaSsaPkcs1Parameters.F4)
                .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
                .setVariant(null)
                .build());
  }

  @Test
  public void buildWithExponentSetToNull_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(null)
                .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
                .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void buildWithTooSmallModulusSize_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(2047)
                .setPublicExponent(RsaSsaPkcs1Parameters.F4)
                .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
                .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void testEqualsAndEqualHashCode() throws Exception {
    RsaSsaPkcs1Parameters parameters1 =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1Parameters parameters2 =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();

    assertThat(parameters1).isEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isEqualTo(parameters2.hashCode());
  }

  @Test
  public void testNotEqual() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters)
        .isNotEqualTo(
            RsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(2049)
                .setPublicExponent(RsaSsaPkcs1Parameters.F4)
                .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
                .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                .build());
    assertThat(parameters)
        .isNotEqualTo(
            RsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(BigInteger.valueOf(65539))
                .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
                .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                .build());
    assertThat(parameters)
        .isNotEqualTo(
            RsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(RsaSsaPkcs1Parameters.F4)
                .setHashType(RsaSsaPkcs1Parameters.HashType.SHA384)
                .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                .build());
    assertThat(parameters)
        .isNotEqualTo(
            RsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(RsaSsaPkcs1Parameters.F4)
                .setHashType(RsaSsaPkcs1Parameters.HashType.SHA384)
                .setVariant(RsaSsaPkcs1Parameters.Variant.TINK)
                .build());
  }
}
