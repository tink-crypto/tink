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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class XChaCha20Poly1305ParametersTest {
  private static final XChaCha20Poly1305Parameters.Variant NO_PREFIX =
      XChaCha20Poly1305Parameters.Variant.NO_PREFIX;
  private static final XChaCha20Poly1305Parameters.Variant TINK =
      XChaCha20Poly1305Parameters.Variant.TINK;
  private static final XChaCha20Poly1305Parameters.Variant CRUNCHY =
      XChaCha20Poly1305Parameters.Variant.CRUNCHY;

  @Test
  public void buildParametersAndGetProperties() throws Exception {
    XChaCha20Poly1305Parameters parameters = XChaCha20Poly1305Parameters.create();
    assertThat(parameters.getVariant()).isEqualTo(NO_PREFIX);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void buildParameters_setVariantExplicitly() throws Exception {
    XChaCha20Poly1305Parameters parameters =
        XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.NO_PREFIX);
    assertThat(parameters.getVariant()).isEqualTo(NO_PREFIX);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void buildParameters_tink() throws Exception {
    XChaCha20Poly1305Parameters parameters =
        XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK);
    assertThat(parameters.getVariant()).isEqualTo(TINK);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void buildParameters_crunchy() throws Exception {
    XChaCha20Poly1305Parameters parameters =
        XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.CRUNCHY);
    assertThat(parameters.getVariant()).isEqualTo(CRUNCHY);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void testEqualsAndEqualHashCode_noPrefix() throws Exception {
    XChaCha20Poly1305Parameters parametersNoPrefix0 = XChaCha20Poly1305Parameters.create();
    XChaCha20Poly1305Parameters parametersNoPrefix1 =
        XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.NO_PREFIX);
    assertThat(parametersNoPrefix0).isEqualTo(parametersNoPrefix1);
    assertThat(parametersNoPrefix0.hashCode()).isEqualTo(parametersNoPrefix1.hashCode());
  }

  @Test
  public void testEqualsAndEqualHashCode_tink() throws Exception {
    XChaCha20Poly1305Parameters parametersTink0 =
        XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK);
    XChaCha20Poly1305Parameters parametersTink1 =
        XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK);
    assertThat(parametersTink0).isEqualTo(parametersTink1);
    assertThat(parametersTink0.hashCode()).isEqualTo(parametersTink1.hashCode());
  }

  @Test
  public void testEqualsAndEqualHashCode_crunchy() throws Exception {
    XChaCha20Poly1305Parameters parametersCrunchy0 =
        XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.CRUNCHY);
    XChaCha20Poly1305Parameters parametersCrunchy1 =
        XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.CRUNCHY);
    assertThat(parametersCrunchy0).isEqualTo(parametersCrunchy1);
    assertThat(parametersCrunchy0.hashCode()).isEqualTo(parametersCrunchy1.hashCode());
  }

  @Test
  public void testEqualsAndEqualHashCode_different() throws Exception {
    XChaCha20Poly1305Parameters parametersNoPrefix = XChaCha20Poly1305Parameters.create();

    XChaCha20Poly1305Parameters parametersTink =
        XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK);

    XChaCha20Poly1305Parameters parametersCrunchy =
        XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.CRUNCHY);

    assertThat(parametersNoPrefix).isNotEqualTo(parametersTink);
    assertThat(parametersNoPrefix.hashCode()).isNotEqualTo(parametersTink.hashCode());

    assertThat(parametersNoPrefix).isNotEqualTo(parametersCrunchy);
    assertThat(parametersNoPrefix.hashCode()).isNotEqualTo(parametersCrunchy.hashCode());

    assertThat(parametersTink).isNotEqualTo(parametersNoPrefix);
    assertThat(parametersTink.hashCode()).isNotEqualTo(parametersNoPrefix.hashCode());

    assertThat(parametersTink).isNotEqualTo(parametersCrunchy);
    assertThat(parametersTink.hashCode()).isNotEqualTo(parametersCrunchy.hashCode());

    assertThat(parametersCrunchy).isNotEqualTo(parametersNoPrefix);
    assertThat(parametersCrunchy.hashCode()).isNotEqualTo(parametersNoPrefix.hashCode());

    assertThat(parametersCrunchy).isNotEqualTo(parametersTink);
    assertThat(parametersCrunchy.hashCode()).isNotEqualTo(parametersTink.hashCode());
  }
}
