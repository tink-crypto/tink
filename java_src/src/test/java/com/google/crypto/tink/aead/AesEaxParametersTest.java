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

import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class AesEaxParametersTest {
  private static final AesEaxParameters.Variant NO_PREFIX = AesEaxParameters.Variant.NO_PREFIX;
  private static final AesEaxParameters.Variant TINK = AesEaxParameters.Variant.TINK;
  private static final AesEaxParameters.Variant CRUNCHY = AesEaxParameters.Variant.CRUNCHY;

  @Test
  public void buildParametersAndGetProperties() throws Exception {
    AesEaxParameters parameters =
        AesEaxParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(NO_PREFIX)
            .build();
    assertThat(parameters.getKeySizeBytes()).isEqualTo(16);
    assertThat(parameters.getIvSizeBytes()).isEqualTo(16);
    assertThat(parameters.getTagSizeBytes()).isEqualTo(16);
    assertThat(parameters.getVariant()).isEqualTo(NO_PREFIX);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void buildParametersWithoutSettingVariant_hasNoPrefix() throws Exception {
    AesEaxParameters parameters =
        AesEaxParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .build();
    assertThat(parameters.getVariant()).isEqualTo(NO_PREFIX);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void buildParametersWithoutSettingKeySize_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesEaxParameters.builder()
                .setIvSizeBytes(16)
                .setTagSizeBytes(16)
                .setVariant(NO_PREFIX)
                .build());
  }

  @Test
  public void buildParametersWithoutSettingIvSize_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesEaxParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(16)
                .setVariant(NO_PREFIX)
                .build());
  }

  @Test
  public void buildParametersWithoutSettingTagSize_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesEaxParameters.builder()
                .setKeySizeBytes(16)
                .setIvSizeBytes(16)
                .setVariant(NO_PREFIX)
                .build());
  }

  @Test
  public void buildWithVariantSetToNull_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesEaxParameters.builder()
                .setKeySizeBytes(16)
                .setIvSizeBytes(16)
                .setVariant(null)
                .build());
  }

  @Test
  public void buildParametersWithTinkPrefix() throws Exception {
    AesEaxParameters parameters =
        AesEaxParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(TINK)
            .build();
    assertThat(parameters.getKeySizeBytes()).isEqualTo(16);
    assertThat(parameters.getIvSizeBytes()).isEqualTo(16);
    assertThat(parameters.getTagSizeBytes()).isEqualTo(16);
    assertThat(parameters.getVariant()).isEqualTo(TINK);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void buildParametersWithCrunchyPrefix() throws Exception {
    AesEaxParameters parameters =
        AesEaxParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(CRUNCHY)
            .build();
    assertThat(parameters.getKeySizeBytes()).isEqualTo(16);
    assertThat(parameters.getIvSizeBytes()).isEqualTo(16);
    assertThat(parameters.getTagSizeBytes()).isEqualTo(16);
    assertThat(parameters.getVariant()).isEqualTo(CRUNCHY);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void testEqualsAndEqualHashCode() throws Exception {
    AesEaxParameters parameters1 =
        AesEaxParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(NO_PREFIX)
            .build();
    AesEaxParameters parameters2 =
        AesEaxParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(NO_PREFIX)
            .build();
    assertThat(parameters1).isEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isEqualTo(parameters2.hashCode());
  }

  @Test
  public void buildParametersWithKeySize16And32() throws Exception {
    AesEaxParameters parameters =
        AesEaxParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(NO_PREFIX)
            .build();
    assertThat(parameters.getKeySizeBytes()).isEqualTo(16);
    parameters =
        AesEaxParameters.builder()
            .setKeySizeBytes(32)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(NO_PREFIX)
            .build();
    assertThat(parameters.getKeySizeBytes()).isEqualTo(32);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesEaxParameters.builder()
                .setKeySizeBytes(8)
                .setIvSizeBytes(16)
                .setTagSizeBytes(16)
                .setVariant(NO_PREFIX)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesEaxParameters.builder()
                .setKeySizeBytes(12)
                .setIvSizeBytes(16)
                .setTagSizeBytes(16)
                .setVariant(NO_PREFIX)
                .build());
  }

  @Test
  public void buildParametersWithLargerTagSizeFails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesEaxParameters.builder()
                .setKeySizeBytes(16)
                .setIvSizeBytes(16)
                .setTagSizeBytes(32)
                .setVariant(NO_PREFIX)
                .build());
  }

  @Test
  public void buildParametersWithIvSize12And16() throws Exception {
    AesEaxParameters parameters =
        AesEaxParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(NO_PREFIX)
            .build();
    assertThat(parameters.getIvSizeBytes()).isEqualTo(12);
    parameters =
        AesEaxParameters.builder()
            .setKeySizeBytes(32)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(NO_PREFIX)
            .build();
    assertThat(parameters.getIvSizeBytes()).isEqualTo(16);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesEaxParameters.builder()
                .setKeySizeBytes(16)
                .setIvSizeBytes(8)
                .setTagSizeBytes(16)
                .setVariant(NO_PREFIX)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesEaxParameters.builder()
                .setKeySizeBytes(16)
                .setIvSizeBytes(22)
                .setTagSizeBytes(16)
                .setVariant(NO_PREFIX)
                .build());
  }

  @Test
  public void testNotEqualandNotEqualHashCode() throws Exception {
    AesEaxParameters parameters1 =
        AesEaxParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(NO_PREFIX)
            .build();

    AesEaxParameters parameters2 =
        AesEaxParameters.builder()
            .setKeySizeBytes(32)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(NO_PREFIX)
            .build();
    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());

    parameters2 =
        AesEaxParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(NO_PREFIX)
            .build();
    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());

    parameters2 =
        AesEaxParameters.builder()
            .setKeySizeBytes(32)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(NO_PREFIX)
            .build();
    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());

    parameters2 =
        AesEaxParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(TINK)
            .build();
    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());

    parameters2 =
        AesEaxParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(CRUNCHY)
            .build();
    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());
  }
}
