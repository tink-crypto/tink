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

package com.google.crypto.tink.aead;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class AesCtrHmacAeadParametersTest {
  @Test
  public void buildParametersAndGetProperties() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(21)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters.getAesKeySizeBytes()).isEqualTo(16);
    assertThat(parameters.getHmacKeySizeBytes()).isEqualTo(16);
    assertThat(parameters.getCiphertextOverheadSizeBytes()).isEqualTo(37);
    assertThat(parameters.getTagSizeBytes()).isEqualTo(21);
    assertThat(parameters.getHashType()).isEqualTo(AesCtrHmacAeadParameters.HashType.SHA256);
    assertThat(parameters.getVariant()).isEqualTo(AesCtrHmacAeadParameters.Variant.NO_PREFIX);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void buildParametersWithoutSettingVariant_hasNoPrefix() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(21)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA512)
            .build();
    assertThat(parameters.getCiphertextOverheadSizeBytes()).isEqualTo(37);
    assertThat(parameters.getTagSizeBytes()).isEqualTo(21);
    assertThat(parameters.getVariant()).isEqualTo(AesCtrHmacAeadParameters.Variant.NO_PREFIX);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void buildParametersWithoutSettingAesKeySize_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCtrHmacAeadParameters.builder()
                .setHmacKeySizeBytes(16)
                .setTagSizeBytes(21)
                .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void buildParametersWithoutSettingHmacKeySize_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCtrHmacAeadParameters.builder()
                .setAesKeySizeBytes(16)
                .setTagSizeBytes(21)
                .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void buildParametersWithoutSettingTagSize_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCtrHmacAeadParameters.builder()
                .setAesKeySizeBytes(16)
                .setHmacKeySizeBytes(16)
                .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void buildParametersWithoutSettingHashType_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCtrHmacAeadParameters.builder()
                .setAesKeySizeBytes(16)
                .setHmacKeySizeBytes(16)
                .setTagSizeBytes(21)
                .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void buildParametersWithVariantSetToNull_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCtrHmacAeadParameters.builder()
                .setAesKeySizeBytes(16)
                .setHmacKeySizeBytes(16)
                .setTagSizeBytes(21)
                .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                .setVariant(null)
                .build());
  }

  @Test
  public void buildParametersWithTinkPrefix() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(21)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
            .build();
    assertThat(parameters.getCiphertextOverheadSizeBytes()).isEqualTo(42);
    assertThat(parameters.getTagSizeBytes()).isEqualTo(21);
    assertThat(parameters.getVariant()).isEqualTo(AesCtrHmacAeadParameters.Variant.TINK);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void buildParametersWithCrunchyPrefix() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(21)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.CRUNCHY)
            .build();
    assertThat(parameters.getCiphertextOverheadSizeBytes()).isEqualTo(42);
    assertThat(parameters.getTagSizeBytes()).isEqualTo(21);
    assertThat(parameters.getVariant()).isEqualTo(AesCtrHmacAeadParameters.Variant.CRUNCHY);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void buildParametersWithBadAesKeySize_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCtrHmacAeadParameters.builder()
                .setAesKeySizeBytes(40)
                .setHmacKeySizeBytes(16)
                .setTagSizeBytes(21)
                .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void buildParametersWithBadHmacKeySize_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCtrHmacAeadParameters.builder()
                .setAesKeySizeBytes(16)
                .setHmacKeySizeBytes(12)
                .setTagSizeBytes(21)
                .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void buildParametersWithSha1_acceptsTagSizesBetween10And20() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCtrHmacAeadParameters.builder()
                .setAesKeySizeBytes(16)
                .setHmacKeySizeBytes(16)
                .setTagSizeBytes(9)
                .setHashType(AesCtrHmacAeadParameters.HashType.SHA1)
                .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCtrHmacAeadParameters.builder()
                .setAesKeySizeBytes(16)
                .setHmacKeySizeBytes(16)
                .setTagSizeBytes(21)
                .setHashType(AesCtrHmacAeadParameters.HashType.SHA1)
                .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                .build());

    AesCtrHmacAeadParameters unused =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA1)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();
    unused =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(20)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA1)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();
  }

  @Test
  public void buildParametersWithSha224_acceptsTagSizesBetween10And28() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCtrHmacAeadParameters.builder()
                .setAesKeySizeBytes(16)
                .setHmacKeySizeBytes(16)
                .setTagSizeBytes(9)
                .setHashType(AesCtrHmacAeadParameters.HashType.SHA224)
                .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCtrHmacAeadParameters.builder()
                .setAesKeySizeBytes(16)
                .setHmacKeySizeBytes(16)
                .setTagSizeBytes(29)
                .setHashType(AesCtrHmacAeadParameters.HashType.SHA224)
                .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                .build());

    AesCtrHmacAeadParameters unused =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA224)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();
    unused =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(28)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA224)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();
  }

  @Test
  public void buildParametersWithSha256_acceptsTagSizesBetween10And32() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCtrHmacAeadParameters.builder()
                .setAesKeySizeBytes(16)
                .setHmacKeySizeBytes(16)
                .setTagSizeBytes(9)
                .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCtrHmacAeadParameters.builder()
                .setAesKeySizeBytes(16)
                .setHmacKeySizeBytes(16)
                .setTagSizeBytes(33)
                .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                .build());

    AesCtrHmacAeadParameters unused =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();
    unused =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(32)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();
  }

  @Test
  public void buildParametersWithSha384_acceptsTagSizesBetween10And48() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCtrHmacAeadParameters.builder()
                .setAesKeySizeBytes(16)
                .setHmacKeySizeBytes(16)
                .setTagSizeBytes(9)
                .setHashType(AesCtrHmacAeadParameters.HashType.SHA384)
                .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCtrHmacAeadParameters.builder()
                .setAesKeySizeBytes(16)
                .setHmacKeySizeBytes(16)
                .setTagSizeBytes(49)
                .setHashType(AesCtrHmacAeadParameters.HashType.SHA384)
                .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                .build());
    AesCtrHmacAeadParameters unused =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA384)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();
    unused =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(48)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA384)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();
  }

  @Test
  public void buildParametersWithSha512_acceptsTagSizesBetween10And64() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCtrHmacAeadParameters.builder()
                .setAesKeySizeBytes(16)
                .setHmacKeySizeBytes(16)
                .setTagSizeBytes(9)
                .setHashType(AesCtrHmacAeadParameters.HashType.SHA512)
                .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesCtrHmacAeadParameters.builder()
                .setAesKeySizeBytes(16)
                .setHmacKeySizeBytes(16)
                .setTagSizeBytes(65)
                .setHashType(AesCtrHmacAeadParameters.HashType.SHA512)
                .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                .build());
    AesCtrHmacAeadParameters unused =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA512)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();
    unused =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(64)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA512)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();
  }

  @Test
  public void testEqualsAndEqualHashCode() throws Exception {
    AesCtrHmacAeadParameters parameters1 =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(21)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();
    AesCtrHmacAeadParameters parameters2 =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(21)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();

    assertThat(parameters1).isEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isEqualTo(parameters2.hashCode());
  }

  @Test
  public void testNotEqualandNotEqualHashCode() throws Exception {
    AesCtrHmacAeadParameters parameters1 =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(21)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();

    AesCtrHmacAeadParameters parameters2 =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(21)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());

    parameters2 =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(22)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());

    parameters2 =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(21)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA384)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());

    parameters2 =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(21)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
            .build();
    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());
  }
}
