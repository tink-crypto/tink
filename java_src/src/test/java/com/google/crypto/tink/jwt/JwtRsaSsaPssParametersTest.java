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

package com.google.crypto.tink.jwt;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public final class JwtRsaSsaPssParametersTest {

  @DataPoints("algorithms")
  public static final JwtRsaSsaPssParameters.Algorithm[] ALGORITHMS =
      new JwtRsaSsaPssParameters.Algorithm[] {
        JwtRsaSsaPssParameters.Algorithm.PS256,
        JwtRsaSsaPssParameters.Algorithm.PS384,
        JwtRsaSsaPssParameters.Algorithm.PS512
      };

  @Theory
  public void buildParametersAndGetProperties_hasExpectedValues(
      @FromDataPoints("algorithms") JwtRsaSsaPssParameters.Algorithm algorithm) throws Exception {
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setAlgorithm(algorithm)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .build();
    assertThat(parameters.getModulusSizeBits()).isEqualTo(2048);
    assertThat(parameters.getPublicExponent()).isEqualTo(JwtRsaSsaPssParameters.F4);
    assertThat(parameters.getKidStrategy()).isEqualTo(JwtRsaSsaPssParameters.KidStrategy.IGNORED);
    assertThat(parameters.getAlgorithm()).isEqualTo(algorithm);
    assertThat(parameters.hasIdRequirement()).isFalse();
    assertThat(parameters.allowKidAbsent()).isTrue();
  }

  @Test
  public void buildParameters_kidCustom_succeds() throws Exception {
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.CUSTOM)
            .build();
    assertThat(parameters.getKidStrategy()).isEqualTo(JwtRsaSsaPssParameters.KidStrategy.CUSTOM);
    assertThat(parameters.hasIdRequirement()).isFalse();
    assertThat(parameters.allowKidAbsent()).isTrue();
  }

  @Test
  public void buildParameters_kidBase64_succeds() throws Exception {
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build();
    assertThat(parameters.getKidStrategy())
        .isEqualTo(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID);
    assertThat(parameters.hasIdRequirement()).isTrue();
    assertThat(parameters.allowKidAbsent()).isFalse();
  }

  @Test
  public void buildParameters_withoutExponent_isF4() throws Exception {
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .build();
    assertThat(parameters.getPublicExponent()).isEqualTo(JwtRsaSsaPssParameters.F4);
  }

  @Test
  public void buildParameters_withLargeModulusSize_succeds() throws Exception {
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(16789)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .build();
    assertThat(parameters.getModulusSizeBits()).isEqualTo(16789);
  }

  @Test
  public void buildParameters_withTooSmallModulusSize_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(2047)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                .build());
  }

  @Test
  public void buildParameters_withValidNonF4PublicExponent_succeds() throws Exception {
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(BigInteger.valueOf(1234567))
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS512)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.CUSTOM)
            .build();
    assertThat(parameters.getPublicExponent()).isEqualTo(BigInteger.valueOf(1234567));
  }

  @Test
  public void buildParameters_withSmallPublicExponent_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(BigInteger.valueOf(3))
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                .build());
  }

  @Test
  public void buildParameters_withEvenPublicExponent_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(BigInteger.valueOf(1234568))
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                .build());
  }

  // Public exponents larger than 2^256 are rejected. See:
  // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf, B.3
  @Test
  public void buildParameters_withTooLargePublicExponent_fails() throws Exception {
    BigInteger tooLargeE = BigInteger.valueOf(2).pow(256).add(BigInteger.ONE);
    assertThat(tooLargeE.bitLength()).isEqualTo(257);
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(tooLargeE)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                .build());
  }

  @Test
  public void buildParameters_withoutSettingModulusSize_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtRsaSsaPssParameters.builder()
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                .build());
  }

  @Test
  public void buildParameters_withoutSettingAlgorithm_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                .build());
  }

  @Test
  public void buildParameters_withoutSettingKidStrategy_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                .build());
  }

  @Test
  public void testEqualsAndEqualsHashCode_succeds() throws Exception {
    JwtRsaSsaPssParameters parameters1 =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .build();
    JwtRsaSsaPssParameters parameters2 =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .build();
    assertThat(parameters1).isEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isEqualTo(parameters2.hashCode());
  }

  @Test
  public void testEqualsHashCode_dependsOnModulusSize() throws Exception {
    JwtRsaSsaPssParameters parameters1 =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .build();
    JwtRsaSsaPssParameters parameters2 =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2049)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .build();
    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());
  }

  @Test
  public void testEqualsHashCode_dependsOnPublicExponent() throws Exception {
    JwtRsaSsaPssParameters parameters1 =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .build();
    JwtRsaSsaPssParameters parameters2 =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(BigInteger.valueOf(65539))
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .build();
    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());
  }

  @Test
  public void testEqualsHashCode_dependsOnAlgorithm() throws Exception {
    JwtRsaSsaPssParameters parameters1 =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .build();
    JwtRsaSsaPssParameters parameters2 =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS384)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .build();
    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());
  }

  @Test
  public void testEqualsHashCode_dependsOnKidStrategy() throws Exception {
    JwtRsaSsaPssParameters parameters1 =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .build();
    JwtRsaSsaPssParameters parameters2 =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.CUSTOM)
            .build();
    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());
  }
}
