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

package com.google.crypto.tink.mac;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class HmacParametersTest {

  // Size of the prefix in bytes
  private static final int PREFIX_SIZE = 5;

  @Test
  public void buildParametersAndGetProperties() throws Exception {
    HmacParameters parameters =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(21)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters.getKeySizeBytes()).isEqualTo(16);
    assertThat(parameters.getCryptographicTagSizeBytes()).isEqualTo(21);
    assertThat(parameters.getTotalTagSizeBytes()).isEqualTo(21);
    assertThat(parameters.getHashType()).isEqualTo(HmacParameters.HashType.SHA256);
    assertThat(parameters.getVariant()).isEqualTo(HmacParameters.Variant.NO_PREFIX);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void buildParametersWithoutSettingVariant_hasNoPrefix() throws Exception {
    HmacParameters parameters =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(21)
            .setHashType(HmacParameters.HashType.SHA256)
            .build();
    assertThat(parameters.getCryptographicTagSizeBytes()).isEqualTo(21);
    assertThat(parameters.getTotalTagSizeBytes()).isEqualTo(21);
    assertThat(parameters.getVariant()).isEqualTo(HmacParameters.Variant.NO_PREFIX);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void buildParametersWithoutSettingKeySize_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacParameters.builder()
                .setTagSizeBytes(21)
                .setHashType(HmacParameters.HashType.SHA256)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void buildParametersWithoutSettingTagSize_fails() throws Exception {
   assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setHashType(HmacParameters.HashType.SHA256)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void buildParametersWithoutSettingHashType_fails() throws Exception {
   assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(21)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void buildParametersWithNoPrefix() throws Exception {
    HmacParameters parameters =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(21)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters.getCryptographicTagSizeBytes()).isEqualTo(21);
    assertThat(parameters.getTotalTagSizeBytes()).isEqualTo(21);
    assertThat(parameters.getVariant()).isEqualTo(HmacParameters.Variant.NO_PREFIX);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void buildParametersWithTinkPrefix() throws Exception {
    HmacParameters parameters =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(21)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.TINK)
            .build();
    assertThat(parameters.getCryptographicTagSizeBytes()).isEqualTo(21);
    assertThat(parameters.getTotalTagSizeBytes()).isEqualTo(21 + PREFIX_SIZE);
    assertThat(parameters.getVariant()).isEqualTo(HmacParameters.Variant.TINK);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void buildParametersWithLegacyPrefix() throws Exception {
    HmacParameters parameters =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(21)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.LEGACY)
            .build();
    assertThat(parameters.getCryptographicTagSizeBytes()).isEqualTo(21);
    assertThat(parameters.getTotalTagSizeBytes()).isEqualTo(21 + PREFIX_SIZE);
    assertThat(parameters.getVariant()).isEqualTo(HmacParameters.Variant.LEGACY);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void buildParametersWithCrunchyPrefix() throws Exception {
    HmacParameters parameters =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(21)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.CRUNCHY)
            .build();
    assertThat(parameters.getCryptographicTagSizeBytes()).isEqualTo(21);
    assertThat(parameters.getTotalTagSizeBytes()).isEqualTo(21 + PREFIX_SIZE);
    assertThat(parameters.getVariant()).isEqualTo(HmacParameters.Variant.CRUNCHY);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void buildParametersWithSha256() throws Exception {
    HmacParameters parameters =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(21)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.CRUNCHY)
            .build();
    assertThat(parameters.getHashType()).isEqualTo(HmacParameters.HashType.SHA256);
  }

  @Test
  public void buildParametersWithSha384() throws Exception {
    HmacParameters parameters =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(21)
            .setHashType(HmacParameters.HashType.SHA384)
            .setVariant(HmacParameters.Variant.CRUNCHY)
            .build();
    assertThat(parameters.getHashType()).isEqualTo(HmacParameters.HashType.SHA384);
  }

  @Test
  public void buildParametersWithSha512() throws Exception {
    HmacParameters parameters =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(21)
            .setHashType(HmacParameters.HashType.SHA512)
            .setVariant(HmacParameters.Variant.CRUNCHY)
            .build();
    assertThat(parameters.getHashType()).isEqualTo(HmacParameters.HashType.SHA512);
  }

  @Test
  public void buildParametersWithSha1_acceptsTagSizesBetween10And20() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(0)
                .setHashType(HmacParameters.HashType.SHA1)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(9)
                .setHashType(HmacParameters.HashType.SHA1)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
    HmacParameters unused =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setHashType(HmacParameters.HashType.SHA1)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    unused =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(20)
            .setHashType(HmacParameters.HashType.SHA1)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(21)
                .setHashType(HmacParameters.HashType.SHA1)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(32)
                .setHashType(HmacParameters.HashType.SHA1)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void buildParametersWithSha224_acceptsTagSizesBetween10And28() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(0)
                .setHashType(HmacParameters.HashType.SHA224)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(9)
                .setHashType(HmacParameters.HashType.SHA224)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
    HmacParameters unused =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setHashType(HmacParameters.HashType.SHA224)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    unused =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(28)
            .setHashType(HmacParameters.HashType.SHA224)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(29)
                .setHashType(HmacParameters.HashType.SHA224)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(32)
                .setHashType(HmacParameters.HashType.SHA224)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void buildParametersWithSha256_acceptsTagSizesBetween10And32() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(0)
                .setHashType(HmacParameters.HashType.SHA256)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(9)
                .setHashType(HmacParameters.HashType.SHA256)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
    HmacParameters unused =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    unused =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(32)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(33)
                .setHashType(HmacParameters.HashType.SHA256)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(64)
                .setHashType(HmacParameters.HashType.SHA256)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void buildParametersWithSha384_acceptsTagSizesBetween10And48() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(0)
                .setHashType(HmacParameters.HashType.SHA384)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(9)
                .setHashType(HmacParameters.HashType.SHA384)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
    HmacParameters unused =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setHashType(HmacParameters.HashType.SHA384)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    unused =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(48)
            .setHashType(HmacParameters.HashType.SHA384)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(49)
                .setHashType(HmacParameters.HashType.SHA384)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(64)
                .setHashType(HmacParameters.HashType.SHA384)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void buildParametersWithSha512_acceptsTagSizesBetween10And64() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(0)
                .setHashType(HmacParameters.HashType.SHA512)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(9)
                .setHashType(HmacParameters.HashType.SHA512)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
    HmacParameters unused =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setHashType(HmacParameters.HashType.SHA512)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    unused =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(64)
            .setHashType(HmacParameters.HashType.SHA512)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(65)
                .setHashType(HmacParameters.HashType.SHA512)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(128)
                .setHashType(HmacParameters.HashType.SHA512)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void testEqualsAndEqualHashCode() throws Exception {
    HmacParameters parameters1 =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(21)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    HmacParameters parameters2 =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(21)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();

    assertThat(parameters1).isEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isEqualTo(parameters2.hashCode());
  }

  @Test
  public void testNotEqual() throws Exception {
    HmacParameters parameters =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(21)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters)
        .isNotEqualTo(
            HmacParameters.builder()
                .setKeySizeBytes(32)
                .setTagSizeBytes(21)
                .setHashType(HmacParameters.HashType.SHA256)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
    assertThat(parameters)
        .isNotEqualTo(
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(22)
                .setHashType(HmacParameters.HashType.SHA256)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
    assertThat(parameters)
        .isNotEqualTo(
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(21)
                .setHashType(HmacParameters.HashType.SHA384)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .build());
    assertThat(parameters)
        .isNotEqualTo(
            HmacParameters.builder()
                .setKeySizeBytes(16)
                .setTagSizeBytes(21)
                .setHashType(HmacParameters.HashType.SHA256)
                .setVariant(HmacParameters.Variant.TINK)
                .build());
  }
}
