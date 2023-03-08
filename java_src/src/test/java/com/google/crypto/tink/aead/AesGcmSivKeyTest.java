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

package com.google.crypto.tink.aead;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.internal.KeyTester;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class AesGcmSivKeyTest {
  @Test
  public void buildNoPrefixVariantAndGetProperties() throws Exception {
    AesGcmSivParameters parameters =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(16)
            .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters.hasIdRequirement()).isFalse();
    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    AesGcmSivKey key =
        AesGcmSivKey.builder().setParameters(parameters).setKeyBytes(keyBytes).build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void buildTinkVariantAndGetProperties() throws Exception {
    AesGcmSivParameters parameters =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(16)
            .setVariant(AesGcmSivParameters.Variant.TINK)
            .build();
    assertThat(parameters.hasIdRequirement()).isTrue();
    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    AesGcmSivKey key =
        AesGcmSivKey.builder()
            .setParameters(parameters)
            .setKeyBytes(keyBytes)
            .setIdRequirement(0x66AABBCC)
            .build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0166AABBCC")));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
  }

  @Test
  public void buildCrunchyVariantAndGetProperties() throws Exception {
    AesGcmSivParameters parameters =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(32)
            .setVariant(AesGcmSivParameters.Variant.CRUNCHY)
            .build();
    assertThat(parameters.hasIdRequirement()).isTrue();
    SecretBytes keyBytes = SecretBytes.randomBytes(32);
    AesGcmSivKey key =
        AesGcmSivKey.builder()
            .setParameters(parameters)
            .setKeyBytes(keyBytes)
            .setIdRequirement(0x66AABBCC)
            .build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0066AABBCC")));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
  }

  @Test
  public void emptyBuild_fails() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> AesGcmSivKey.builder().build());
  }

  @Test
  public void buildWithoutParameters_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> AesGcmSivKey.builder().setKeyBytes(SecretBytes.randomBytes(32)).build());
  }

  @Test
  public void buildWithoutKeyBytes_fails() throws Exception {
    AesGcmSivParameters parameters =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(16)
            .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> AesGcmSivKey.builder().setParameters(parameters).build());
  }

  @Test
  public void paramtersRequireIdButIdIsNotSetInBuild_fails() throws Exception {
    AesGcmSivParameters parametersWithIdRequirement =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(16)
            .setVariant(AesGcmSivParameters.Variant.TINK)
            .build();
    assertThat(parametersWithIdRequirement.hasIdRequirement()).isTrue();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesGcmSivKey.builder()
                .setKeyBytes(SecretBytes.randomBytes(16))
                .setParameters(parametersWithIdRequirement)
                .build());
  }

  @Test
  public void buildBadKeySize_fails() throws Exception {
    AesGcmSivParameters parameters =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(32)
            .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesGcmSivKey.builder()
                .setParameters(parameters)
                .setKeyBytes(SecretBytes.randomBytes(16))
                .build());
  }

  @Test
  public void testEqualities() throws Exception {
    SecretBytes keyBytes32 = SecretBytes.randomBytes(32);
    SecretBytes keyBytes32Copy =
        SecretBytes.copyFrom(
            keyBytes32.toByteArray(InsecureSecretKeyAccess.get()), InsecureSecretKeyAccess.get());
    SecretBytes keyBytes32Diff = SecretBytes.randomBytes(32);
    SecretBytes keyBytes16 = SecretBytes.randomBytes(16);

    AesGcmSivParameters noPrefixParametersKeySize32 =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(32)
            .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
            .build();
    AesGcmSivParameters noPrefixParametersKeySize16 =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(16)
            .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
            .build();
    AesGcmSivParameters tinkPrefixParametersKeySize32 =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(32)
            .setVariant(AesGcmSivParameters.Variant.TINK)
            .build();
    AesGcmSivParameters crunchyPrefixParametersKeySize32 =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(32)
            .setVariant(AesGcmSivParameters.Variant.CRUNCHY)
            .build();

    new KeyTester()
        .addEqualityGroup(
            "No prefix, keyBytes32",
            AesGcmSivKey.builder()
                .setParameters(noPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32)
                .build(),
            // The same key built twice must be equal.
            AesGcmSivKey.builder()
                .setParameters(noPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32)
                .build(),
            // The same key built with a copy of key bytes must be equal.
            AesGcmSivKey.builder()
                .setParameters(noPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32Copy)
                .build(),
            // Setting id requirement to null is equal to not setting it.
            AesGcmSivKey.builder()
                .setParameters(noPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32)
                .setIdRequirement(null)
                .build())
        // This group checks that keys with different key bytes are not equal.
        .addEqualityGroup(
            "No prefix, newly generated keyBytes32",
            AesGcmSivKey.builder()
                .setParameters(noPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32Diff)
                .build())
        // This group checks that keys with different key sizes are not equal.
        .addEqualityGroup(
            "No prefix, keyBytes16",
            AesGcmSivKey.builder()
                .setParameters(noPrefixParametersKeySize16)
                .setKeyBytes(keyBytes16)
                .build())
        .addEqualityGroup(
            "Tink with key id 1907, keyBytes32",
            AesGcmSivKey.builder()
                .setParameters(tinkPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32)
                .setIdRequirement(1907)
                .build(),
            AesGcmSivKey.builder()
                .setParameters(tinkPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32Copy)
                .setIdRequirement(1907)
                .build())
        // This group checks that keys with different key ids are not equal.
        .addEqualityGroup(
            "Tink with key id 1908, keyBytes32",
            AesGcmSivKey.builder()
                .setParameters(tinkPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32)
                .setIdRequirement(1908)
                .build())
        // This groups checks that keys with different output prefix types are not equal.
        .addEqualityGroup(
            "Crunchy with key id 1907, keyBytes32",
            AesGcmSivKey.builder()
                .setParameters(crunchyPrefixParametersKeySize32)
                .setKeyBytes(keyBytes32)
                .setIdRequirement(1907)
                .build())
        .doTests();
  }

  @Test
  public void testDifferentKeyTypesEquality_fails() throws Exception {
    AesGcmSivParameters aesGcmSivParameters =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(16)
            .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
            .build();

    AesGcmParameters aesGcmParameters =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build();

    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    AesGcmKey aesGcmKey =
        AesGcmKey.builder().setParameters(aesGcmParameters).setKeyBytes(keyBytes).build();
    AesGcmSivKey aesGcmSivKey =
        AesGcmSivKey.builder().setParameters(aesGcmSivParameters).setKeyBytes(keyBytes).build();

    assertThat(aesGcmSivKey.equalsKey(aesGcmKey)).isFalse();
  }
}
