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
public final class AesGcmParametersTest {
  private static final AesGcmParameters.Variant NO_PREFIX = AesGcmParameters.Variant.NO_PREFIX;
  private static final AesGcmParameters.Variant TINK = AesGcmParameters.Variant.TINK;
  private static final AesGcmParameters.Variant CRUNCHY = AesGcmParameters.Variant.CRUNCHY;

  @Test
  public void buildParametersAndGetProperties() throws Exception {
    AesGcmParameters parameters =
        AesGcmParameters.builder()
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
    AesGcmParameters parameters =
        AesGcmParameters.builder()
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
            AesGcmParameters.builder()
                .setVariant(NO_PREFIX)
                .setIvSizeBytes(16)
                .setTagSizeBytes(16)
                .build());
  }

  @Test
  public void buildParametersWithoutSettingIvSize_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesGcmParameters.builder()
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
            AesGcmParameters.builder()
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
            AesGcmParameters.builder()
                .setKeySizeBytes(16)
                .setIvSizeBytes(16)
                .setTagSizeBytes(16)
                .setVariant(null)
                .build());
  }

  @Test
  public void buildParametersWithTinkPrefix() throws Exception {
    AesGcmParameters parameters =
        AesGcmParameters.builder()
            .setKeySizeBytes(24)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(TINK)
            .build();
    assertThat(parameters.getKeySizeBytes()).isEqualTo(24);
    assertThat(parameters.getVariant()).isEqualTo(TINK);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void buildParametersWithCrunchyPrefix() throws Exception {
    AesGcmParameters parameters =
        AesGcmParameters.builder()
            .setKeySizeBytes(32)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(CRUNCHY)
            .build();
    assertThat(parameters.getKeySizeBytes()).isEqualTo(32);
    assertThat(parameters.getVariant()).isEqualTo(CRUNCHY);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void testEqualsAndEqualHashCode() throws Exception {
    AesGcmParameters parameters1 =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(NO_PREFIX)
            .build();
    AesGcmParameters parameters2 =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(NO_PREFIX)
            .build();
    assertThat(parameters1).isEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isEqualTo(parameters2.hashCode());
  }

  @Test
  public void buildParametersWithBadKeySizeFails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesGcmParameters.builder()
                .setKeySizeBytes(12)
                .setIvSizeBytes(16)
                .setTagSizeBytes(16)
                .setVariant(NO_PREFIX)
                .build());

    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesGcmParameters.builder()
                .setKeySizeBytes(34)
                .setIvSizeBytes(16)
                .setTagSizeBytes(16)
                .setVariant(NO_PREFIX)
                .build());
  }

  @Test
  public void buildParametersWithBadTagSizeFails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesGcmParameters.builder()
                .setKeySizeBytes(16)
                .setIvSizeBytes(16)
                .setTagSizeBytes(17)
                .setVariant(NO_PREFIX)
                .build());
  }

  @Test
  public void buildParametersWithBadIvSizeFails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            AesGcmParameters.builder()
                .setKeySizeBytes(16)
                .setIvSizeBytes(0)
                .setTagSizeBytes(17)
                .setVariant(NO_PREFIX)
                .build());
  }

  @Test
  public void testNotEqualandNotEqualHashCode() throws Exception {
    AesGcmParameters parameters1 =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(NO_PREFIX)
            .build();

    AesGcmParameters parameters2 =
        AesGcmParameters.builder()
            .setKeySizeBytes(24)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(NO_PREFIX)
            .build();
    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());

    parameters2 =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(14)
            .setVariant(NO_PREFIX)
            .build();
    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());

    parameters2 =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(TINK)
            .build();
    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());

    parameters2 =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(CRUNCHY)
            .build();
    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());
  }
}
