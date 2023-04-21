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

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.internal.KeyTester;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.HmacParameters;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.util.Optional;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class JwtHmacKeyTest {
  @Test
  public void buildSimpleVariantCheckProperties() throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    JwtHmacKey key = JwtHmacKey.builder().setParameters(parameters).setKeyBytes(keyBytes).build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getKid()).isEqualTo(Optional.empty());
  }

  @Test
  public void buildWithoutKeyBytes_throws() throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    JwtHmacKey.Builder builder = JwtHmacKey.builder().setParameters(parameters);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void build_kidStrategyIgnored_WithCustomKid_throws() throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    JwtHmacKey.Builder builder =
        JwtHmacKey.builder()
            .setParameters(parameters)
            .setCustomKid("customKid")
            .setKeyBytes(keyBytes);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void build_kidStrategyIgnored_withIdRequirement_throws() throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    JwtHmacKey.Builder builder =
        JwtHmacKey.builder().setParameters(parameters).setIdRequirement(120).setKeyBytes(keyBytes);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void build_kidStrategyCustom() throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS384)
            .setKidStrategy(JwtHmacParameters.KidStrategy.CUSTOM)
            .build();
    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    JwtHmacKey key =
        JwtHmacKey.builder()
            .setParameters(parameters)
            .setKeyBytes(keyBytes)
            .setCustomKid("CustomKid")
            .build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getKid()).isEqualTo(Optional.of("CustomKid"));
  }

  @Test
  public void build_kidStrategyCustom_differentAlgorithmAndKeyId_works() throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.CUSTOM)
            .build();
    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    JwtHmacKey key =
        JwtHmacKey.builder()
            .setParameters(parameters)
            .setKeyBytes(keyBytes)
            .setCustomKid("myCustomTestKid")
            .build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getKid()).isEqualTo(Optional.of("myCustomTestKid"));
  }

  @Test
  public void build_kidStrategyCustom_doNotSetCustomKid_throws() throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.CUSTOM)
            .build();
    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    JwtHmacKey.Builder builder =
        JwtHmacKey.builder().setParameters(parameters).setKeyBytes(keyBytes);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void build_kidStrategyCustom_setIdRequirement_throws() throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.CUSTOM)
            .build();
    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    JwtHmacKey.Builder builder =
        JwtHmacKey.builder()
            .setParameters(parameters)
            .setCustomKid("myCustomTestKid")
            .setKeyBytes(keyBytes)
            .setIdRequirement(2930);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void build_kidStrategyBase64_setCustomKeyId_throws() throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS384)
            .setKidStrategy(JwtHmacParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build();
    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    JwtHmacKey.Builder builder =
        JwtHmacKey.builder()
            .setParameters(parameters)
            .setKeyBytes(keyBytes)
            .setIdRequirement(0x89abcdef)
            .setCustomKid("customKeyId");
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void build_kidStrategyBase64_omitIdRequirement_throws() throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS384)
            .setKidStrategy(JwtHmacParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build();
    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    JwtHmacKey.Builder builder =
        JwtHmacKey.builder().setParameters(parameters).setKeyBytes(keyBytes);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testEqualities() throws Exception {
    SecretBytes keyBytes16 = SecretBytes.randomBytes(16);
    SecretBytes keyBytes16Copy =
        SecretBytes.copyFrom(
            keyBytes16.toByteArray(InsecureSecretKeyAccess.get()), InsecureSecretKeyAccess.get());
    SecretBytes keyBytes16B = SecretBytes.randomBytes(16);
    SecretBytes keyBytes32 = SecretBytes.randomBytes(32);

    JwtHmacParameters parametersIgnoredKidStrategy =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    JwtHmacParameters parametersIgnoredKidStrategyCopy =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    JwtHmacParameters parametersHS384 =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS384)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    JwtHmacParameters parametersHS512 =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS512)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    JwtHmacParameters parametersKeySize32 =
        JwtHmacParameters.builder()
            .setKeySizeBytes(32)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    JwtHmacParameters parametersKidStrategyCustom =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.CUSTOM)
            .build();
    JwtHmacParameters parametersKidStrategyBase64 =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build();
    new KeyTester()
        .addEqualityGroup(
            "StrategyKidIgnored",
            JwtHmacKey.builder()
                .setParameters(parametersIgnoredKidStrategy)
                .setKeyBytes(keyBytes16)
                .build(),
            // the same key built twice must be equal
            JwtHmacKey.builder()
                .setParameters(parametersIgnoredKidStrategy)
                .setKeyBytes(keyBytes16)
                .build(),
            // the same key built with a copy of key bytes and parameters must be equal
            JwtHmacKey.builder()
                .setParameters(parametersIgnoredKidStrategyCopy)
                .setKeyBytes(keyBytes16Copy)
                .build())
        .addEqualityGroup(
            "keyBytes16B",
            JwtHmacKey.builder()
                .setParameters(parametersIgnoredKidStrategy)
                .setKeyBytes(keyBytes16B)
                .build())
        .addEqualityGroup(
            "parametersHS384",
            JwtHmacKey.builder().setParameters(parametersHS384).setKeyBytes(keyBytes16).build())
        .addEqualityGroup(
            "parametersHS512",
            JwtHmacKey.builder().setParameters(parametersHS512).setKeyBytes(keyBytes16).build())
        .addEqualityGroup(
            "parameters32BytesKey",
            JwtHmacKey.builder().setParameters(parametersKeySize32).setKeyBytes(keyBytes32).build())
        .addEqualityGroup(
            "custom Kid 1",
            JwtHmacKey.builder()
                .setParameters(parametersKidStrategyCustom)
                .setKeyBytes(keyBytes16)
                .setCustomKid("myCustomKid1")
                .build())
        .addEqualityGroup(
            "custom Kid 2",
            JwtHmacKey.builder()
                .setParameters(parametersKidStrategyCustom)
                .setKeyBytes(keyBytes16)
                .setCustomKid("myCustomKid2")
                .build())
        .addEqualityGroup(
            "base64Id101",
            JwtHmacKey.builder()
                .setParameters(parametersKidStrategyBase64)
                .setKeyBytes(keyBytes16)
                .setIdRequirement(101)
                .build())
        .addEqualityGroup(
            "base64Id102",
            JwtHmacKey.builder()
                .setParameters(parametersKidStrategyBase64)
                .setKeyBytes(keyBytes16)
                .setIdRequirement(102)
                .build())
        .doTests();
  }

  @Test
  public void testDifferentKeyTypesEquality_fails() throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(16)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    JwtHmacKey key = JwtHmacKey.builder().setParameters(parameters).setKeyBytes(keyBytes).build();

    HmacParameters hmacParameters =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    HmacKey hmacKey = HmacKey.builder().setParameters(hmacParameters).setKeyBytes(keyBytes).build();

    assertThat(key.equalsKey(hmacKey)).isFalse();
  }
}
