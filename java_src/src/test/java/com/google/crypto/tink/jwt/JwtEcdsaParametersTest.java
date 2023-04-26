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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class JwtEcdsaParametersTest {
  @Test
  public void buildParametersAndGetProperties_es256() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .build();
    assertThat(parameters.getKidStrategy()).isEqualTo(JwtEcdsaParameters.KidStrategy.IGNORED);
    assertThat(parameters.getAlgorithm()).isEqualTo(JwtEcdsaParameters.Algorithm.ES256);
    assertThat(parameters.hasIdRequirement()).isFalse();
    assertThat(parameters.allowKidAbsent()).isTrue();
  }

  @Test
  public void buildParametersAndGetProperties_es384() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .build();
    assertThat(parameters.getKidStrategy()).isEqualTo(JwtEcdsaParameters.KidStrategy.IGNORED);
    assertThat(parameters.getAlgorithm()).isEqualTo(JwtEcdsaParameters.Algorithm.ES384);
    assertThat(parameters.hasIdRequirement()).isFalse();
    assertThat(parameters.allowKidAbsent()).isTrue();
  }

  @Test
  public void buildParametersAndGetProperties_es512() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .build();
    assertThat(parameters.getKidStrategy()).isEqualTo(JwtEcdsaParameters.KidStrategy.IGNORED);
    assertThat(parameters.getAlgorithm()).isEqualTo(JwtEcdsaParameters.Algorithm.ES512);
    assertThat(parameters.hasIdRequirement()).isFalse();
    assertThat(parameters.allowKidAbsent()).isTrue();
  }

  @Test
  public void buildParametersAndGetProperties_kidCustom() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.CUSTOM)
            .build();
    assertThat(parameters.getKidStrategy()).isEqualTo(JwtEcdsaParameters.KidStrategy.CUSTOM);
    assertThat(parameters.getAlgorithm()).isEqualTo(JwtEcdsaParameters.Algorithm.ES256);
    assertThat(parameters.hasIdRequirement()).isFalse();
    assertThat(parameters.allowKidAbsent()).isTrue();
  }

  @Test
  public void buildParametersAndGetProperties_kidBase64() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build();
    assertThat(parameters.getKidStrategy())
        .isEqualTo(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID);
    assertThat(parameters.getAlgorithm()).isEqualTo(JwtEcdsaParameters.Algorithm.ES256);
    assertThat(parameters.hasIdRequirement()).isTrue();
    assertThat(parameters.allowKidAbsent()).isFalse();
  }

  @Test
  public void testEqualsTwoInstances() throws Exception {
    JwtEcdsaParameters parameters1 =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .build();
    JwtEcdsaParameters parameters2 =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .build();
    assertThat(parameters1).isEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isEqualTo(parameters2.hashCode());
  }

  @Test
  public void testEqualsHashCodeDependsOnAlgorithm() throws Exception {
    JwtEcdsaParameters parameters1 =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .build();
    JwtEcdsaParameters parameters2 =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .build();
    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());
  }

  @Test
  public void testEqualsHashCodeDependsOnKidStrategy() throws Exception {
    JwtEcdsaParameters parameters1 =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .build();
    JwtEcdsaParameters parameters2 =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build();
    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());
  }
}
