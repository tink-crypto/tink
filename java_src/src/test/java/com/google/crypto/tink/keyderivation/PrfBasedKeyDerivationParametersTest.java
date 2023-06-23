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

package com.google.crypto.tink.keyderivation;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.aead.XChaCha20Poly1305Parameters;
import com.google.crypto.tink.mac.HmacParameters;
import com.google.crypto.tink.prf.AesCmacPrfParameters;
import com.google.crypto.tink.prf.HmacPrfParameters;
import com.google.crypto.tink.prf.PrfParameters;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class PrfBasedKeyDerivationParametersTest {
  private static final PrfParameters PRF_PARAMETERS_1 =
      exceptionIsBug(() -> AesCmacPrfParameters.create(16));
  private static final PrfParameters PRF_PARAMETERS_2 =
      exceptionIsBug(
          () ->
              HmacPrfParameters.builder()
                  .setKeySizeBytes(16)
                  .setHashType(HmacPrfParameters.HashType.SHA256)
                  .build());
  private static final Parameters DERIVED_PARAMETERS_1 =
      exceptionIsBug(() -> XChaCha20Poly1305Parameters.create());
  private static final Parameters DERIVED_PARAMETERS_2 =
      exceptionIsBug(
          () ->
              HmacParameters.builder()
                  .setKeySizeBytes(16)
                  .setTagSizeBytes(16)
                  .setVariant(HmacParameters.Variant.NO_PREFIX)
                  .setHashType(HmacParameters.HashType.SHA1)
                  .build());

  @Test
  public void testCreateAndGet_works() throws Exception {
    PrfBasedKeyDerivationParameters params =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(PRF_PARAMETERS_1)
            .setDerivedKeyParameters(DERIVED_PARAMETERS_1)
            .build();
    assertThat(params.getPrfParameters()).isEqualTo(PRF_PARAMETERS_1);
    assertThat(params.getDerivedKeyParameters()).isEqualTo(DERIVED_PARAMETERS_1);
  }

  @Test
  public void test_missingPrfParameters_throws() throws Exception {
    PrfBasedKeyDerivationParameters.Builder builder =
        PrfBasedKeyDerivationParameters.builder().setDerivedKeyParameters(DERIVED_PARAMETERS_1);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void test_missingDerivedKeyParameters_throws() throws Exception {
    PrfBasedKeyDerivationParameters.Builder builder =
        PrfBasedKeyDerivationParameters.builder().setPrfParameters(PRF_PARAMETERS_1);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void test_equals_hashCode_works() throws Exception {
    PrfBasedKeyDerivationParameters params11 =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(PRF_PARAMETERS_1)
            .setDerivedKeyParameters(DERIVED_PARAMETERS_1)
            .build();
    PrfBasedKeyDerivationParameters params11Copy =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(PRF_PARAMETERS_1)
            .setDerivedKeyParameters(DERIVED_PARAMETERS_1)
            .build();
    PrfBasedKeyDerivationParameters params12 =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(PRF_PARAMETERS_1)
            .setDerivedKeyParameters(DERIVED_PARAMETERS_2)
            .build();
    PrfBasedKeyDerivationParameters params21 =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(PRF_PARAMETERS_2)
            .setDerivedKeyParameters(DERIVED_PARAMETERS_1)
            .build();
    PrfBasedKeyDerivationParameters params22 =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(PRF_PARAMETERS_2)
            .setDerivedKeyParameters(DERIVED_PARAMETERS_2)
            .build();

    assertThat(params11).isEqualTo(params11Copy);

    assertThat(params11).isNotEqualTo(params12);
    assertThat(params11).isNotEqualTo(params21);
    assertThat(params11).isNotEqualTo(params22);

    assertThat(params12).isNotEqualTo(params11);
    assertThat(params12).isNotEqualTo(params21);
    assertThat(params12).isNotEqualTo(params22);

    assertThat(params21).isNotEqualTo(params11);
    assertThat(params21).isNotEqualTo(params12);
    assertThat(params21).isNotEqualTo(params22);

    assertThat(params22).isNotEqualTo(params11);
    assertThat(params22).isNotEqualTo(params12);
    assertThat(params22).isNotEqualTo(params21);

    assertThat(params11.hashCode()).isEqualTo(params11Copy.hashCode());
    assertThat(params11.hashCode()).isNotEqualTo(params12.hashCode());
    assertThat(params11.hashCode()).isNotEqualTo(params21.hashCode());
    assertThat(params11.hashCode()).isNotEqualTo(params22.hashCode());
  }
}
