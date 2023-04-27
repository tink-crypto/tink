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
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import java.util.Optional;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class JwtEcdsaPublicKeyTest {
  private static final ECPoint A_P256_POINT =
      new ECPoint(
          new BigInteger("700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287", 16),
          new BigInteger("db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac", 16));

  private static final ECPoint INVALID_P256_POINT =
      new ECPoint(
          new BigInteger("700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287", 16),
          new BigInteger("db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ad", 16));

  private static final ECPoint A_P384_POINT =
      new ECPoint(
          new BigInteger(
              "a7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27fe7513272"
                  + "734466b400091adbf2d68c58e0c50066",
              16),
          new BigInteger(
              "ac68f19f2e1cb879aed43a9969b91a0839c4c38a49749b661efedf243451915e"
                  + "d0905a32b060992b468c64766fc8437a",
              16));

  private static final ECPoint A_P521_POINT =
      new ECPoint(
          new BigInteger(
              "000000685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a9490340"
                  + "854334b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2"
                  + "046d",
              16),
          new BigInteger(
              "000001ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b7398"
                  + "84a83bde99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302"
                  + "f676",
              16));

  @Test
  public void build_kidStrategyIgnored_getProperties_es256() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();
    JwtEcdsaPublicKey key =
        JwtEcdsaPublicKey.builder().setParameters(parameters).setPublicPoint(A_P256_POINT).build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getPublicPoint()).isEqualTo(A_P256_POINT);
    assertThat(key.getKid()).isEqualTo(Optional.empty());
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void build_kidStrategyIgnored_andGetProperties_es384() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
            .build();
    JwtEcdsaPublicKey key =
        JwtEcdsaPublicKey.builder().setParameters(parameters).setPublicPoint(A_P384_POINT).build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getPublicPoint()).isEqualTo(A_P384_POINT);
    assertThat(key.getKid()).isEqualTo(Optional.empty());
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void build_kidStrategyIgnored_andGetProperties_es512() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
            .build();
    JwtEcdsaPublicKey key =
        JwtEcdsaPublicKey.builder().setParameters(parameters).setPublicPoint(A_P521_POINT).build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getPublicPoint()).isEqualTo(A_P521_POINT);
    assertThat(key.getKid()).isEqualTo(Optional.empty());
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void build_kidStrategyIgnored_setCustomKidCalled_fails() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();
    JwtEcdsaPublicKey.Builder builder =
        JwtEcdsaPublicKey.builder()
            .setParameters(parameters)
            .setCustomKid("customKid23")
            .setPublicPoint(A_P256_POINT);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void build_kidStrategyIgnored_setIdRequirement_fails() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();
    JwtEcdsaPublicKey.Builder builder =
        JwtEcdsaPublicKey.builder()
            .setParameters(parameters)
            .setIdRequirement(123)
            .setPublicPoint(A_P256_POINT);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void buildKidStrategyCustom_getProperties_succeeds() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.CUSTOM)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();
    JwtEcdsaPublicKey key =
        JwtEcdsaPublicKey.builder()
            .setCustomKid("customKid777")
            .setParameters(parameters)
            .setPublicPoint(A_P256_POINT)
            .build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getPublicPoint()).isEqualTo(A_P256_POINT);
    assertThat(key.getKid().get()).isEqualTo("customKid777");
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void buildKidStrategyCustom_setIdRequirement_fails() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.CUSTOM)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();
    JwtEcdsaPublicKey.Builder builder =
        JwtEcdsaPublicKey.builder()
            .setCustomKid("customKid777")
            .setIdRequirement(1234)
            .setParameters(parameters)
            .setPublicPoint(A_P256_POINT);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void buildKidStrategyCustom_missingCustomKid_fails() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.CUSTOM)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();
    JwtEcdsaPublicKey.Builder builder =
        JwtEcdsaPublicKey.builder().setParameters(parameters).setPublicPoint(A_P256_POINT);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void build_kidStrategyBase64_getProperties_succeeds() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();
    JwtEcdsaPublicKey key =
        JwtEcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(A_P256_POINT)
            .setIdRequirement(0x1ac6a944)
            .build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x1ac6a944);
    // See JwtFormatTest.getKidFromTinkOutputPrefixType_success
    assertThat(key.getKid()).isEqualTo(Optional.of("GsapRA"));
  }

  @Test
  public void build_kidStrategyBase64_noIdRequirement_throws() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();
    JwtEcdsaPublicKey.Builder builder =
        JwtEcdsaPublicKey.builder().setParameters(parameters).setPublicPoint(A_P256_POINT);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void build_kidStrategyBase64_setCustomKid_throws() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();
    JwtEcdsaPublicKey.Builder builder =
        JwtEcdsaPublicKey.builder()
            .setParameters(parameters)
            .setIdRequirement(0x89abcdef)
            .setCustomKid("customKid")
            .setPublicPoint(A_P256_POINT);
    assertThrows(GeneralSecurityException.class, builder::build);
  }


  @Test
  public void emptyBuild_fails() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> JwtEcdsaPublicKey.builder().build());
  }

  @Test
  public void buildWithoutParameters_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> JwtEcdsaPublicKey.builder().setPublicPoint(A_P256_POINT).build());
  }

  @Test
  public void buildWithoutPublicPoint_fails() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> JwtEcdsaPublicKey.builder().setParameters(parameters).build());
  }

  @Test
  public void build_invalidPublicPoint_fails() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();
    JwtEcdsaPublicKey.Builder builder =
        JwtEcdsaPublicKey.builder().setParameters(parameters).setPublicPoint(INVALID_P256_POINT);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testEqualities() throws Exception {
    ECPoint aP256PointCopy =
        new ECPoint(
            new BigInteger("700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287", 16),
            new BigInteger("db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac", 16));
    ECPoint anotherP256Point =
        new ECPoint(
            new BigInteger("809f04289c64348c01515eb03d5ce7ac1a8cb9498f5caa50197e58d43a86a7ae", 16),
            new BigInteger("b29d84e811197f25eba8f5194092cb6ff440e26d4421011372461f579271cda3", 16));

    JwtEcdsaParameters kidStrategyIgnoredParameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();
    JwtEcdsaParameters kidStrategyIgnoredParametersCopy =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();

    JwtEcdsaParameters kidStrategyCustomParameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.CUSTOM)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();

    JwtEcdsaParameters kidStrategyBase64Parameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();

    new KeyTester()
        .addEqualityGroup(
            "KID Ignored, P256",
            JwtEcdsaPublicKey.builder()
                .setParameters(kidStrategyIgnoredParameters)
                .setPublicPoint(A_P256_POINT)
                .build(),
            // the same key built twice must be equal
            JwtEcdsaPublicKey.builder()
                .setParameters(kidStrategyIgnoredParameters)
                .setPublicPoint(A_P256_POINT)
                .build(),
            // the same key built with a copy of key bytes must be equal
            JwtEcdsaPublicKey.builder()
                .setParameters(kidStrategyIgnoredParameters)
                .setPublicPoint(aP256PointCopy)
                .build(),
            // the same key built with a copy of parameters must be equal
            JwtEcdsaPublicKey.builder()
                .setParameters(kidStrategyIgnoredParametersCopy)
                .setPublicPoint(A_P256_POINT)
                .build())
        // This group checks that keys with different key bytes are not equal
        .addEqualityGroup(
            "KID Ignored, different P256 point",
            JwtEcdsaPublicKey.builder()
                .setParameters(kidStrategyIgnoredParameters)
                .setPublicPoint(anotherP256Point)
                .build())
        // These groups checks that keys with different customKid are not equal
        .addEqualityGroup(
            "KID Custom, customKid1",
            JwtEcdsaPublicKey.builder()
                .setParameters(kidStrategyCustomParameters)
                .setPublicPoint(A_P256_POINT)
                .setCustomKid("customKid1")
                .build())
        .addEqualityGroup(
            "KID Custom, customKid2",
            JwtEcdsaPublicKey.builder()
                .setParameters(kidStrategyCustomParameters)
                .setPublicPoint(A_P256_POINT)
                .setCustomKid("customKid2")
                .build())
        // These groups checks that keys with different ID Requirements are not equal
        .addEqualityGroup(
            "Tink with key id 1907, P256",
            JwtEcdsaPublicKey.builder()
                .setParameters(kidStrategyBase64Parameters)
                .setPublicPoint(A_P256_POINT)
                .setIdRequirement(1907)
                .build(),
            JwtEcdsaPublicKey.builder()
                .setParameters(kidStrategyBase64Parameters)
                .setPublicPoint(aP256PointCopy)
                .setIdRequirement(1907)
                .build())
        // This group checks that keys with different key ids are not equal
        .addEqualityGroup(
            "Tink with key id 1908, P256",
            JwtEcdsaPublicKey.builder()
                .setParameters(kidStrategyBase64Parameters)
                .setPublicPoint(A_P256_POINT)
                .setIdRequirement(1908)
                .build())
        .doTests();
  }
}
