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
public final class JwtHmacParametersTest {
  @Test
  public void buildParametersAndGetProperties() throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    assertThat(parameters.hasIdRequirement()).isFalse();
    assertThat(parameters.getKeySizeBytes()).isEqualTo(16);
    assertThat(parameters.getKidStrategy()).isEqualTo(JwtHmacParameters.KidStrategy.IGNORED);
    assertThat(parameters.getAlgorithm()).isEqualTo(JwtHmacParameters.Algorithm.HS256);
    assertThat(parameters.hasIdRequirement()).isFalse();
    assertThat(parameters.allowKidAbsent()).isTrue();
  }

  @Test
  public void buildParametersAndGetProperties_differentAlgorithm() throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS512)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    assertThat(parameters.getAlgorithm()).isEqualTo(JwtHmacParameters.Algorithm.HS512);
  }

  @Test
  public void buildParametersAndGetProperties_kidCustom() throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.CUSTOM)
            .build();
    assertThat(parameters.getKidStrategy()).isEqualTo(JwtHmacParameters.KidStrategy.CUSTOM);
    assertThat(parameters.hasIdRequirement()).isFalse();
    assertThat(parameters.allowKidAbsent()).isTrue();
  }

  @Test
  public void buildParametersAndGetProperties_kidBase64() throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build();
    assertThat(parameters.getKidStrategy()).isEqualTo(JwtHmacParameters.KidStrategy.BASE64_ENCODED_KEY_ID);
    assertThat(parameters.hasIdRequirement()).isTrue();
    assertThat(parameters.allowKidAbsent()).isFalse();
  }

  @Test
  public void buildParameters_differentKeySize() throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(17)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    assertThat(parameters.getKeySizeBytes()).isEqualTo(17);
  }

  @Test
  public void testEqualsTwoInstances() throws Exception {
    JwtHmacParameters parameters1 =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    JwtHmacParameters parameters2 =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    assertThat(parameters1).isEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isEqualTo(parameters2.hashCode());
  }

  @Test
  public void testEqualsHashCodeDependsOnKeySize() throws Exception {
    JwtHmacParameters parameters1 =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    JwtHmacParameters parameters2 =
        JwtHmacParameters.builder()
            .setKeySizeBytes(17)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());
  }

  @Test
  public void testEqualsHashCodeDependsOnAlgorithm() throws Exception {
    JwtHmacParameters parameters1 =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    JwtHmacParameters parameters2 =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS384)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());
  }

  @Test
  public void testEqualsHashCodeDependsOnKidStrategy() throws Exception {
    JwtHmacParameters parameters1 =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    JwtHmacParameters parameters2 =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build();
    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());
  }
}
