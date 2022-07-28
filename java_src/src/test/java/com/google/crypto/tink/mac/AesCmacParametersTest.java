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
public final class AesCmacParametersTest {
  private static final AesCmacParameters.Variant NO_PREFIX = AesCmacParameters.Variant.NO_PREFIX;
  private static final AesCmacParameters.Variant TINK = AesCmacParameters.Variant.TINK;
  private static final AesCmacParameters.Variant LEGACY = AesCmacParameters.Variant.LEGACY;
  private static final AesCmacParameters.Variant CRUNCHY = AesCmacParameters.Variant.CRUNCHY;

  private static AesCmacParameters generalCreate(int tagSize, AesCmacParameters.Variant variant)
      throws GeneralSecurityException {
    return AesCmacParameters.createForKeysetWithCryptographicTagSize(tagSize, variant);
  }

  @Test
  public void testAesCmacParameters_basic() throws Exception {
    AesCmacParameters parameters = AesCmacParameters.create(16);
    assertThat(parameters.getCryptographicTagSizeBytes()).isEqualTo(16);
    assertThat(parameters.getTotalTagSizeBytes()).isEqualTo(16);
    assertThat(parameters.getVariant()).isEqualTo(NO_PREFIX);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void testAesCmacParameters_variant() throws Exception {
    assertThat(generalCreate(16, NO_PREFIX).getVariant()).isEqualTo(NO_PREFIX);
    assertThat(generalCreate(16, TINK).getVariant()).isEqualTo(TINK);
    assertThat(generalCreate(16, LEGACY).getVariant()).isEqualTo(LEGACY);
    assertThat(generalCreate(16, CRUNCHY).getVariant()).isEqualTo(CRUNCHY);
  }

  @Test
  public void testAesCmacParameters_hasIdRequirement() throws Exception {
    assertThat(generalCreate(16, NO_PREFIX).hasIdRequirement()).isFalse();
    assertThat(generalCreate(16, TINK).hasIdRequirement()).isTrue();
    assertThat(generalCreate(16, LEGACY).hasIdRequirement()).isTrue();
    assertThat(generalCreate(16, CRUNCHY).hasIdRequirement()).isTrue();
  }

  @Test
  public void testAesCmacParameters_tagSizesConstruction() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> AesCmacParameters.create(5));
    assertThrows(GeneralSecurityException.class, () -> AesCmacParameters.create(6));
    assertThrows(GeneralSecurityException.class, () -> AesCmacParameters.create(7));
    assertThrows(GeneralSecurityException.class, () -> AesCmacParameters.create(8));
    assertThrows(GeneralSecurityException.class, () -> AesCmacParameters.create(9));
    AesCmacParameters.create(10);
    AesCmacParameters.create(11);
    AesCmacParameters.create(12);
    AesCmacParameters.create(13);
    AesCmacParameters.create(14);
    AesCmacParameters.create(15);
    AesCmacParameters.create(16);
    assertThrows(GeneralSecurityException.class, () -> AesCmacParameters.create(17));
    assertThrows(GeneralSecurityException.class, () -> AesCmacParameters.create(18));
    assertThrows(GeneralSecurityException.class, () -> AesCmacParameters.create(19));
    assertThrows(GeneralSecurityException.class, () -> AesCmacParameters.create(20));
    assertThrows(GeneralSecurityException.class, () -> AesCmacParameters.create(21));
    assertThrows(GeneralSecurityException.class, () -> AesCmacParameters.create(32));
  }

  @Test
  public void testAesCmacParameters_tagSizesConstruction2() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> generalCreate(5, TINK));
    assertThrows(GeneralSecurityException.class, () -> generalCreate(6, TINK));
    assertThrows(GeneralSecurityException.class, () -> generalCreate(7, TINK));
    assertThrows(GeneralSecurityException.class, () -> generalCreate(8, TINK));
    assertThrows(GeneralSecurityException.class, () -> generalCreate(9, TINK));
    assertThrows(GeneralSecurityException.class, () -> generalCreate(9, CRUNCHY));
    assertThrows(GeneralSecurityException.class, () -> generalCreate(9, LEGACY));
    generalCreate(10, TINK);
    generalCreate(10, CRUNCHY);
    generalCreate(10, LEGACY);
    generalCreate(11, TINK);
    generalCreate(12, TINK);
    generalCreate(13, TINK);
    generalCreate(14, TINK);
    generalCreate(15, TINK);
    generalCreate(16, TINK);
    generalCreate(16, CRUNCHY);
    generalCreate(16, LEGACY);
    assertThrows(GeneralSecurityException.class, () -> generalCreate(17, CRUNCHY));
    assertThrows(GeneralSecurityException.class, () -> generalCreate(17, LEGACY));
    assertThrows(GeneralSecurityException.class, () -> generalCreate(17, TINK));
    assertThrows(GeneralSecurityException.class, () -> generalCreate(18, TINK));
    assertThrows(GeneralSecurityException.class, () -> generalCreate(21, TINK));
    assertThrows(GeneralSecurityException.class, () -> generalCreate(32, TINK));
  }

  @Test
  public void testAesCmacParameters_getTotalTagSizeBytes() throws Exception {
    assertThat(AesCmacParameters.create(10).getTotalTagSizeBytes()).isEqualTo(10);
    assertThat(AesCmacParameters.create(11).getTotalTagSizeBytes()).isEqualTo(11);
    assertThat(AesCmacParameters.create(12).getTotalTagSizeBytes()).isEqualTo(12);
    assertThat(AesCmacParameters.create(13).getTotalTagSizeBytes()).isEqualTo(13);
    assertThat(AesCmacParameters.create(14).getTotalTagSizeBytes()).isEqualTo(14);
    assertThat(AesCmacParameters.create(15).getTotalTagSizeBytes()).isEqualTo(15);
    assertThat(AesCmacParameters.create(16).getTotalTagSizeBytes()).isEqualTo(16);
    assertThat(generalCreate(10, TINK).getTotalTagSizeBytes()).isEqualTo(15);
    assertThat(generalCreate(10, CRUNCHY).getTotalTagSizeBytes()).isEqualTo(15);
    assertThat(generalCreate(10, LEGACY).getTotalTagSizeBytes()).isEqualTo(15);
    assertThat(generalCreate(13, TINK).getTotalTagSizeBytes()).isEqualTo(18);
    assertThat(generalCreate(13, CRUNCHY).getTotalTagSizeBytes()).isEqualTo(18);
    assertThat(generalCreate(13, LEGACY).getTotalTagSizeBytes()).isEqualTo(18);
    assertThat(generalCreate(16, TINK).getTotalTagSizeBytes()).isEqualTo(21);
    assertThat(generalCreate(16, CRUNCHY).getTotalTagSizeBytes()).isEqualTo(21);
    assertThat(generalCreate(16, LEGACY).getTotalTagSizeBytes()).isEqualTo(21);
  }

  @Test
  public void testAesCmacParameters_getCryptographicTagSizeBytes() throws Exception {
    assertThat(AesCmacParameters.create(10).getCryptographicTagSizeBytes()).isEqualTo(10);
    assertThat(AesCmacParameters.create(11).getCryptographicTagSizeBytes()).isEqualTo(11);
    assertThat(AesCmacParameters.create(12).getCryptographicTagSizeBytes()).isEqualTo(12);
    assertThat(AesCmacParameters.create(13).getCryptographicTagSizeBytes()).isEqualTo(13);
    assertThat(AesCmacParameters.create(14).getCryptographicTagSizeBytes()).isEqualTo(14);
    assertThat(AesCmacParameters.create(15).getCryptographicTagSizeBytes()).isEqualTo(15);
    assertThat(AesCmacParameters.create(16).getCryptographicTagSizeBytes()).isEqualTo(16);
    assertThat(generalCreate(10, TINK).getCryptographicTagSizeBytes()).isEqualTo(10);
    assertThat(generalCreate(10, CRUNCHY).getCryptographicTagSizeBytes()).isEqualTo(10);
    assertThat(generalCreate(10, LEGACY).getCryptographicTagSizeBytes()).isEqualTo(10);
    assertThat(generalCreate(13, TINK).getCryptographicTagSizeBytes()).isEqualTo(13);
    assertThat(generalCreate(13, CRUNCHY).getCryptographicTagSizeBytes()).isEqualTo(13);
    assertThat(generalCreate(13, LEGACY).getCryptographicTagSizeBytes()).isEqualTo(13);
    assertThat(generalCreate(16, TINK).getCryptographicTagSizeBytes()).isEqualTo(16);
    assertThat(generalCreate(16, CRUNCHY).getCryptographicTagSizeBytes()).isEqualTo(16);
    assertThat(generalCreate(16, LEGACY).getCryptographicTagSizeBytes()).isEqualTo(16);
  }

  @Test
  public void testAesCmacParameters_equal() throws Exception {
    assertThat(AesCmacParameters.create(10)).isEqualTo(generalCreate(10, NO_PREFIX));
    assertThat(AesCmacParameters.create(11)).isEqualTo(generalCreate(11, NO_PREFIX));
    assertThat(AesCmacParameters.create(12)).isEqualTo(generalCreate(12, NO_PREFIX));
    assertThat(AesCmacParameters.create(13)).isEqualTo(generalCreate(13, NO_PREFIX));
    assertThat(AesCmacParameters.create(13)).isEqualTo(generalCreate(13, NO_PREFIX));
    assertThat(generalCreate(16, TINK)).isEqualTo(generalCreate(16, TINK));
    assertThat(generalCreate(16, LEGACY)).isEqualTo(generalCreate(16, LEGACY));
    assertThat(generalCreate(16, CRUNCHY)).isEqualTo(generalCreate(16, CRUNCHY));
  }

  @Test
  public void testAesCmacParameters_notEqual() throws Exception {
    assertThat(generalCreate(10, NO_PREFIX)).isNotEqualTo(generalCreate(11, NO_PREFIX));
    assertThat(generalCreate(10, NO_PREFIX)).isNotEqualTo(generalCreate(10, TINK));
    assertThat(generalCreate(10, TINK)).isNotEqualTo(generalCreate(10, LEGACY));
    assertThat(generalCreate(10, LEGACY)).isNotEqualTo(generalCreate(10, CRUNCHY));
  }

  @Test
  public void testAesCmacParameters_equalHashes() throws Exception {
    assertThat(AesCmacParameters.create(10).hashCode())
        .isEqualTo(generalCreate(10, NO_PREFIX).hashCode());
    assertThat(AesCmacParameters.create(11).hashCode())
        .isEqualTo(generalCreate(11, NO_PREFIX).hashCode());
    assertThat(AesCmacParameters.create(12).hashCode())
        .isEqualTo(generalCreate(12, NO_PREFIX).hashCode());
    assertThat(AesCmacParameters.create(13).hashCode())
        .isEqualTo(generalCreate(13, NO_PREFIX).hashCode());
    assertThat(AesCmacParameters.create(13).hashCode())
        .isEqualTo(generalCreate(13, NO_PREFIX).hashCode());
    assertThat(generalCreate(16, TINK).hashCode()).isEqualTo(generalCreate(16, TINK).hashCode());
    assertThat(generalCreate(16, LEGACY).hashCode())
        .isEqualTo(generalCreate(16, LEGACY).hashCode());
    assertThat(generalCreate(16, CRUNCHY).hashCode())
        .isEqualTo(generalCreate(16, CRUNCHY).hashCode());
  }
}
