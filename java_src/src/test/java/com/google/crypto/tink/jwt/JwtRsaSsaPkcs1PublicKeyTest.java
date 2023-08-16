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

import com.google.crypto.tink.internal.KeyTester;
import com.google.crypto.tink.subtle.Base64;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Optional;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class JwtRsaSsaPkcs1PublicKeyTest {

  // Test vector from https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2
  static final BigInteger MODULUS =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx"
                  + "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs"
                  + "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH"
                  + "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV"
                  + "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8"
                  + "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"));

  @Test
  public void build_kidStrategyIgnored_hasExpectedValues() throws Exception {
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();
    JwtRsaSsaPkcs1PublicKey key =
        JwtRsaSsaPkcs1PublicKey.builder().setParameters(parameters).setModulus(MODULUS).build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getModulus()).isEqualTo(MODULUS);
    assertThat(key.getKid()).isEqualTo(Optional.empty());
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void build_kidStrategyIgnored_setCustomKid_fails() throws Exception {
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();
    JwtRsaSsaPkcs1PublicKey.Builder builder =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(parameters)
            .setModulus(MODULUS)
            .setCustomKid("customKid23");
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void build_kidStrategyIgnored_setIdRequirement_fails() throws Exception {
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();
    JwtRsaSsaPkcs1PublicKey.Builder builder =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(parameters)
            .setIdRequirement(123)
            .setModulus(MODULUS);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void build_kidStrategyCustom_hasExpectedValues() throws Exception {
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.CUSTOM)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();
    JwtRsaSsaPkcs1PublicKey key =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(parameters)
            .setModulus(MODULUS)
            .setCustomKid("customKid777")
            .build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getModulus()).isEqualTo(MODULUS);
    assertThat(key.getKid().get()).isEqualTo("customKid777");
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void build_kidStrategyCustom_setIdRequirement_fails() throws Exception {
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.CUSTOM)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();
    JwtRsaSsaPkcs1PublicKey.Builder builder =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(parameters)
            .setIdRequirement(123)
            .setCustomKid("customKid777")
            .setModulus(MODULUS);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void buildKidStrategyCustom_missingCustomKid_fails() throws Exception {
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.CUSTOM)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();
    JwtRsaSsaPkcs1PublicKey.Builder builder =
        JwtRsaSsaPkcs1PublicKey.builder().setParameters(parameters).setModulus(MODULUS);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void build_kidStrategyBase64_getProperties_succeeds() throws Exception {
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();
    JwtRsaSsaPkcs1PublicKey key =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(parameters)
            .setModulus(MODULUS)
            .setIdRequirement(0x1ac6a944)
            .build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x1ac6a944);
    // See JwtFormatTest.getKidFromTinkOutputPrefixType_success
    assertThat(key.getKid()).isEqualTo(Optional.of("GsapRA"));
  }

  @Test
  public void build_kidStrategyBase64_noIdRequirement_throws() throws Exception {
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();
    JwtRsaSsaPkcs1PublicKey.Builder builder =
        JwtRsaSsaPkcs1PublicKey.builder().setParameters(parameters).setModulus(MODULUS);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void build_kidStrategyBase64_setCustomKid_throws() throws Exception {
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();
    JwtRsaSsaPkcs1PublicKey.Builder builder =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(parameters)
            .setIdRequirement(0x89abcdef)
            .setCustomKid("customKid")
            .setModulus(MODULUS);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void emptyBuild_fails() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> JwtRsaSsaPkcs1PublicKey.builder().build());
  }

  @Test
  public void buildWithoutParameters_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> JwtRsaSsaPkcs1PublicKey.builder().setModulus(MODULUS).build());
  }

  @Test
  public void build_withoutModulus_fails() throws Exception {
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> JwtRsaSsaPkcs1PublicKey.builder().setParameters(parameters).build());
  }

  @Test
  public void build_invalidModulusSize_fails() throws Exception {
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(3456)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();

    // Modulus between 2^3455 and 2^3456 are valid.
    BigInteger tooSmall = BigInteger.valueOf(2).pow(3455).subtract(BigInteger.ONE);
    BigInteger tooBig = BigInteger.valueOf(2).pow(3456).add(BigInteger.ONE);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtRsaSsaPkcs1PublicKey.builder()
                .setParameters(parameters)
                .setModulus(tooSmall)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtRsaSsaPkcs1PublicKey.builder().setParameters(parameters).setModulus(tooBig).build());
  }

  @Test
  public void testEqualities() throws Exception {
    JwtRsaSsaPkcs1Parameters kidStrategyIgnoredParameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();
    JwtRsaSsaPkcs1Parameters kidStrategyIgnoredParametersCopy =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();

    JwtRsaSsaPkcs1Parameters kidStrategyCustomParameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.CUSTOM)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();

    JwtRsaSsaPkcs1Parameters kidStrategyBase64Parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();

    new KeyTester()
        .addEqualityGroup(
            "KID Ignored, R256",
            JwtRsaSsaPkcs1PublicKey.builder()
                .setParameters(kidStrategyIgnoredParameters)
                .setModulus(MODULUS)
                .build(),
            // the same key built twice must be equal
            JwtRsaSsaPkcs1PublicKey.builder()
                .setParameters(kidStrategyIgnoredParameters)
                .setModulus(MODULUS)
                .build(),
            // the same key built with a copy of parameters must be equal
            JwtRsaSsaPkcs1PublicKey.builder()
                .setParameters(kidStrategyIgnoredParametersCopy)
                .setModulus(MODULUS)
                .build())
        // This group checks that keys with different key bytes are not equal
        .addEqualityGroup(
            "KID Ignored, different modulus",
            JwtRsaSsaPkcs1PublicKey.builder()
                .setParameters(kidStrategyIgnoredParameters)
                .setModulus(MODULUS.add(BigInteger.ONE))
                .build())
        // These groups checks that keys with different customKid are not equal
        .addEqualityGroup(
            "KID Custom, customKid1",
            JwtRsaSsaPkcs1PublicKey.builder()
                .setParameters(kidStrategyCustomParameters)
                .setModulus(MODULUS)
                .setCustomKid("customKid1")
                .build())
        .addEqualityGroup(
            "KID Custom, customKid2",
            JwtRsaSsaPkcs1PublicKey.builder()
                .setParameters(kidStrategyCustomParameters)
                .setModulus(MODULUS)
                .setCustomKid("customKid2")
                .build())
        // These groups checks that keys with different ID Requirements are not equal
        .addEqualityGroup(
            "Tink with key id 1907",
            JwtRsaSsaPkcs1PublicKey.builder()
                .setParameters(kidStrategyBase64Parameters)
                .setModulus(MODULUS)
                .setIdRequirement(1907)
                .build())
        .addEqualityGroup(
            "Tink with key id 1908",
            JwtRsaSsaPkcs1PublicKey.builder()
                .setParameters(kidStrategyBase64Parameters)
                .setModulus(MODULUS)
                .setIdRequirement(1908)
                .build())
        .doTests();
  }
}
