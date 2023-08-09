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
public final class JwtRsaSsaPssPublicKeyTest {

  // Test vector from https://www.rfc-editor.org/rfc/rfc7517#appendix-C.1
  static final BigInteger MODULUS =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRy"
                  + "O125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP"
                  + "8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0"
                  + "Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0X"
                  + "OC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1"
                  + "_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q"));

  @Test
  public void build_kidStrategyIgnored_hasExpectedValues() throws Exception {
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();
    JwtRsaSsaPssPublicKey key =
        JwtRsaSsaPssPublicKey.builder().setParameters(parameters).setModulus(MODULUS).build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getModulus()).isEqualTo(MODULUS);
    assertThat(key.getKid()).isEqualTo(Optional.empty());
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void build_kidStrategyIgnored_setCustomKid_fails() throws Exception {
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();
    JwtRsaSsaPssPublicKey.Builder builder =
        JwtRsaSsaPssPublicKey.builder()
            .setParameters(parameters)
            .setModulus(MODULUS)
            .setCustomKid("customKid23");
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void build_kidStrategyIgnored_setIdRequirement_fails() throws Exception {
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();
    JwtRsaSsaPssPublicKey.Builder builder =
        JwtRsaSsaPssPublicKey.builder()
            .setParameters(parameters)
            .setIdRequirement(123)
            .setModulus(MODULUS);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void build_kidStrategyCustom_hasExpectedValues() throws Exception {
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.CUSTOM)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();
    JwtRsaSsaPssPublicKey key =
        JwtRsaSsaPssPublicKey.builder()
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
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.CUSTOM)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();
    JwtRsaSsaPssPublicKey.Builder builder =
        JwtRsaSsaPssPublicKey.builder()
            .setParameters(parameters)
            .setIdRequirement(123)
            .setCustomKid("customKid777")
            .setModulus(MODULUS);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void buildKidStrategyCustom_missingCustomKid_fails() throws Exception {
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.CUSTOM)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();
    JwtRsaSsaPssPublicKey.Builder builder =
        JwtRsaSsaPssPublicKey.builder().setParameters(parameters).setModulus(MODULUS);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void build_kidStrategyBase64_getProperties_succeeds() throws Exception {
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();
    JwtRsaSsaPssPublicKey key =
        JwtRsaSsaPssPublicKey.builder()
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
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();
    JwtRsaSsaPssPublicKey.Builder builder =
        JwtRsaSsaPssPublicKey.builder().setParameters(parameters).setModulus(MODULUS);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void build_kidStrategyBase64_setCustomKid_throws() throws Exception {
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();
    JwtRsaSsaPssPublicKey.Builder builder =
        JwtRsaSsaPssPublicKey.builder()
            .setParameters(parameters)
            .setIdRequirement(0x89abcdef)
            .setCustomKid("customKid")
            .setModulus(MODULUS);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void emptyBuild_fails() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> JwtRsaSsaPssPublicKey.builder().build());
  }

  @Test
  public void buildWithoutParameters_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> JwtRsaSsaPssPublicKey.builder().setModulus(MODULUS).build());
  }

  @Test
  public void build_withoutModulus_fails() throws Exception {
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> JwtRsaSsaPssPublicKey.builder().setParameters(parameters).build());
  }

  @Test
  public void build_invalidModulusSize_fails() throws Exception {
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(3456)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();

    // Modulus between 2^3455 and 2^3456 are valid.
    BigInteger tooSmall = BigInteger.valueOf(2).pow(3455).subtract(BigInteger.ONE);
    BigInteger tooBig = BigInteger.valueOf(2).pow(3456).add(BigInteger.ONE);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtRsaSsaPssPublicKey.builder().setParameters(parameters).setModulus(tooSmall).build());
    assertThrows(
        GeneralSecurityException.class,
        () -> JwtRsaSsaPssPublicKey.builder().setParameters(parameters).setModulus(tooBig).build());
  }

  @Test
  public void testEqualities() throws Exception {
    JwtRsaSsaPssParameters kidStrategyIgnoredParameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();
    JwtRsaSsaPssParameters kidStrategyIgnoredParametersCopy =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();

    JwtRsaSsaPssParameters kidStrategyCustomParameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.CUSTOM)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();

    JwtRsaSsaPssParameters kidStrategyBase64Parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();

    new KeyTester()
        .addEqualityGroup(
            "KID Ignored, R256",
            JwtRsaSsaPssPublicKey.builder()
                .setParameters(kidStrategyIgnoredParameters)
                .setModulus(MODULUS)
                .build(),
            // the same key built twice must be equal
            JwtRsaSsaPssPublicKey.builder()
                .setParameters(kidStrategyIgnoredParameters)
                .setModulus(MODULUS)
                .build(),
            // the same key built with a copy of parameters must be equal
            JwtRsaSsaPssPublicKey.builder()
                .setParameters(kidStrategyIgnoredParametersCopy)
                .setModulus(MODULUS)
                .build())
        // This group checks that keys with different key bytes are not equal
        .addEqualityGroup(
            "KID Ignored, different modulus",
            JwtRsaSsaPssPublicKey.builder()
                .setParameters(kidStrategyIgnoredParameters)
                .setModulus(MODULUS.add(BigInteger.ONE))
                .build())
        // These groups checks that keys with different customKid are not equal
        .addEqualityGroup(
            "KID Custom, customKid1",
            JwtRsaSsaPssPublicKey.builder()
                .setParameters(kidStrategyCustomParameters)
                .setModulus(MODULUS)
                .setCustomKid("customKid1")
                .build())
        .addEqualityGroup(
            "KID Custom, customKid2",
            JwtRsaSsaPssPublicKey.builder()
                .setParameters(kidStrategyCustomParameters)
                .setModulus(MODULUS)
                .setCustomKid("customKid2")
                .build())
        // These groups checks that keys with different ID Requirements are not equal
        .addEqualityGroup(
            "Tink with key id 1907",
            JwtRsaSsaPssPublicKey.builder()
                .setParameters(kidStrategyBase64Parameters)
                .setModulus(MODULUS)
                .setIdRequirement(1907)
                .build())
        .addEqualityGroup(
            "Tink with key id 1908",
            JwtRsaSsaPssPublicKey.builder()
                .setParameters(kidStrategyBase64Parameters)
                .setModulus(MODULUS)
                .setIdRequirement(1908)
                .build())
        .doTests();
  }
}
