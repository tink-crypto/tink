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

package com.google.crypto.tink.signature;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class RsaSsaPssParametersTest {

  @Test
  public void buildWithNoPrefixAndGetProperties() throws Exception {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    assertThat(parameters.getModulusSizeBits()).isEqualTo(2048);
    assertThat(parameters.getPublicExponent()).isEqualTo(RsaSsaPssParameters.F4);
    assertThat(parameters.getSigHashType()).isEqualTo(RsaSsaPssParameters.HashType.SHA256);
    assertThat(parameters.getMgf1HashType()).isEqualTo(RsaSsaPssParameters.HashType.SHA256);
    assertThat(parameters.getVariant()).isEqualTo(RsaSsaPssParameters.Variant.NO_PREFIX);
    assertThat(parameters.getSaltLengthBytes()).isEqualTo(32);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void buildParametersWithoutSettingVariant_hasNoPrefix() throws Exception {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setSaltLengthBytes(32)
            .build();
    assertThat(parameters.getVariant()).isEqualTo(RsaSsaPssParameters.Variant.NO_PREFIX);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void buildParametersWithoutExponent_defaultsToF4() throws Exception {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    assertThat(parameters.getPublicExponent()).isEqualTo(RsaSsaPssParameters.F4);
  }

  @Test
  public void buildParametersWithTinkPrefix() throws Exception {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.TINK)
            .setSaltLengthBytes(32)
            .build();
    assertThat(parameters.getVariant()).isEqualTo(RsaSsaPssParameters.Variant.TINK);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void buildParametersWithLegacyPrefix() throws Exception {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.LEGACY)
            .setSaltLengthBytes(32)
            .build();
    assertThat(parameters.getVariant()).isEqualTo(RsaSsaPssParameters.Variant.LEGACY);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void buildParametersWithCrunchyPrefix() throws Exception {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA512)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA512)
            .setVariant(RsaSsaPssParameters.Variant.CRUNCHY)
            .setSaltLengthBytes(64)
            .build();
    assertThat(parameters.getVariant()).isEqualTo(RsaSsaPssParameters.Variant.CRUNCHY);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void buildParametersWithSha384() throws Exception {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(3072)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA384)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA384)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(48)
            .build();
    assertThat(parameters.getSigHashType()).isEqualTo(RsaSsaPssParameters.HashType.SHA384);
    assertThat(parameters.getMgf1HashType()).isEqualTo(RsaSsaPssParameters.HashType.SHA384);
  }

  @Test
  public void buildParametersWithSha512() throws Exception {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA512)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA512)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(64)
            .build();
    assertThat(parameters.getSigHashType()).isEqualTo(RsaSsaPssParameters.HashType.SHA512);
    assertThat(parameters.getMgf1HashType()).isEqualTo(RsaSsaPssParameters.HashType.SHA512);
  }

  @Test
  public void buildParametersWithLargeModulusSize() throws Exception {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(16789)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA512)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA512)
            .setVariant(RsaSsaPssParameters.Variant.CRUNCHY)
            .setSaltLengthBytes(64)
            .build();
    assertThat(parameters.getModulusSizeBits()).isEqualTo(16789);
  }

  @Test
  public void buildParametersWithValidNonF4PublicExponentSet() throws Exception {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(BigInteger.valueOf(1234567))
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    assertThat(parameters.getPublicExponent()).isEqualTo(BigInteger.valueOf(1234567));
  }

  @Test
  public void buildParametersWithTooSmallModulusSize_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPssParameters.builder()
                .setModulusSizeBits(2047)
                .setPublicExponent(RsaSsaPssParameters.F4)
                .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
                .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
                .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void buildParametersWithSmallPublicExponent_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(BigInteger.valueOf(3))
                .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
                .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
                .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                .setSaltLengthBytes(32)
                .build());
  }

  @Test
  public void buildParametersWithEvenPublicExponent_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(BigInteger.valueOf(1234568))
                .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
                .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
                .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                .setSaltLengthBytes(32)
                .build());
  }

  @Test
  public void buildParametersWithLargePublicExponent_works() throws Exception {
    BigInteger largeE = BigInteger.valueOf(100000000001L);
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(largeE)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
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
            RsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(tooLargeE)
                .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
                .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
                .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                .setSaltLengthBytes(32)
                .build());
  }

  @Test
  public void buildParametersWithoutSettingModulusSize_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPssParameters.builder()
                .setPublicExponent(RsaSsaPssParameters.F4)
                .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
                .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
                .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                .setSaltLengthBytes(32)
                .build());
  }

  @Test
  public void buildParametersWithoutSettingSigHashType_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(RsaSsaPssParameters.F4)
                .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
                .setSaltLengthBytes(32)
                .build());
  }

  @Test
  public void buildParametersWithoutSettingMgf1HashType_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(RsaSsaPssParameters.F4)
                .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
                .setSaltLengthBytes(32)
                .build());
  }

  @Test
  public void buildParametersWithDifferentHashTypes_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(RsaSsaPssParameters.F4)
                .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
                .setMgf1HashType(RsaSsaPssParameters.HashType.SHA512)
                .setSaltLengthBytes(32)
                .build());
  }

  @Test
  public void buildParametersWithoutSettingSaltLength_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(RsaSsaPssParameters.F4)
                .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
                .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
                .build());
  }

  @Test
  public void buildParametersWithVariantSetToNull_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(RsaSsaPssParameters.F4)
                .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
                .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
                .setVariant(null)
                .build());
  }

  @Test
  public void buildParametersWithExponentSetToNull_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(null)
                .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
                .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
                .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void testEqualsAndEqualHashCode() throws Exception {
    RsaSsaPssParameters parameters1 =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    RsaSsaPssParameters parameters2 =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();

    assertThat(parameters1).isEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isEqualTo(parameters2.hashCode());
  }

  @Test
  public void testNotEqual() throws Exception {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    assertThat(parameters)
        .isNotEqualTo(
            RsaSsaPssParameters.builder()
                .setModulusSizeBits(2049)
                .setPublicExponent(RsaSsaPssParameters.F4)
                .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
                .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
                .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                .setSaltLengthBytes(32)
                .build());
    assertThat(parameters)
        .isNotEqualTo(
            RsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(BigInteger.valueOf(65539))
                .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
                .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
                .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                .setSaltLengthBytes(32)
                .build());
    assertThat(parameters)
        .isNotEqualTo(
            RsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(RsaSsaPssParameters.F4)
                .setSigHashType(RsaSsaPssParameters.HashType.SHA384)
                .setMgf1HashType(RsaSsaPssParameters.HashType.SHA384)
                .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                .setSaltLengthBytes(32)
                .build());
    assertThat(parameters)
        .isNotEqualTo(
            RsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(RsaSsaPssParameters.F4)
                .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
                .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
                .setVariant(RsaSsaPssParameters.Variant.TINK)
                .setSaltLengthBytes(32)
                .build());
    assertThat(parameters)
        .isNotEqualTo(
            RsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(RsaSsaPssParameters.F4)
                .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
                .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
                .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                .setSaltLengthBytes(64)
                .build());
  }
}
