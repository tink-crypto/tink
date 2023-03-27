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

package com.google.crypto.tink.signature;

import static com.google.common.truth.Truth.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class Ed25519ParametersTest {
  private static final Ed25519Parameters.Variant NO_PREFIX = Ed25519Parameters.Variant.NO_PREFIX;
  private static final Ed25519Parameters.Variant TINK = Ed25519Parameters.Variant.TINK;
  private static final Ed25519Parameters.Variant CRUNCHY = Ed25519Parameters.Variant.CRUNCHY;
  private static final Ed25519Parameters.Variant LEGACY = Ed25519Parameters.Variant.LEGACY;

  @Test
  public void buildParametersAndGetProperties_noPrefix() throws Exception {
    Ed25519Parameters parameters = Ed25519Parameters.create();
    assertThat(parameters.getVariant()).isEqualTo(NO_PREFIX);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void buildParametersAndGetProperties_noPrefix_setVariantExplicitly() throws Exception {
    Ed25519Parameters parameters = Ed25519Parameters.create(NO_PREFIX);
    assertThat(parameters.getVariant()).isEqualTo(NO_PREFIX);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void buildParametersAndGetProperties_tink() throws Exception {
    Ed25519Parameters parameters = Ed25519Parameters.create(TINK);
    assertThat(parameters.getVariant()).isEqualTo(TINK);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void buildParameterAndGetProperties_crunchy() throws Exception {
    Ed25519Parameters parameters = Ed25519Parameters.create(CRUNCHY);
    assertThat(parameters.getVariant()).isEqualTo(CRUNCHY);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void buildParameterAndGetProperties_legacy() throws Exception {
    Ed25519Parameters parameters = Ed25519Parameters.create(LEGACY);
    assertThat(parameters.getVariant()).isEqualTo(LEGACY);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void testEqualsAndEqualHashCode_noPrefix() throws Exception {
    Ed25519Parameters parametersNoPrefix0 = Ed25519Parameters.create();
    Ed25519Parameters parametersNoPrefix1 = Ed25519Parameters.create();
    assertThat(parametersNoPrefix0).isEqualTo(parametersNoPrefix1);
    assertThat(parametersNoPrefix0.hashCode()).isEqualTo(parametersNoPrefix1.hashCode());
  }

  @Test
  public void testEqualsAndEqualHashCode_tink() throws Exception {
    Ed25519Parameters parametersTink0 = Ed25519Parameters.create(TINK);
    Ed25519Parameters parametersTink1 = Ed25519Parameters.create(TINK);
    assertThat(parametersTink0).isEqualTo(parametersTink1);
    assertThat(parametersTink0.hashCode()).isEqualTo(parametersTink1.hashCode());
  }

  @Test
  public void testEqualsAndEqualHashCode_crunchy() throws Exception {
    Ed25519Parameters parametersCrunchy0 = Ed25519Parameters.create(CRUNCHY);
    Ed25519Parameters parametersCrunchy1 = Ed25519Parameters.create(CRUNCHY);
    assertThat(parametersCrunchy0).isEqualTo(parametersCrunchy1);
    assertThat(parametersCrunchy0.hashCode()).isEqualTo(parametersCrunchy1.hashCode());
  }

  @Test
  public void testEqualsAndEqualHashCode_legacy() throws Exception {
    Ed25519Parameters parametersLegacy0 = Ed25519Parameters.create(LEGACY);
    Ed25519Parameters parametersLegacy1 = Ed25519Parameters.create(LEGACY);
    assertThat(parametersLegacy0).isEqualTo(parametersLegacy1);
    assertThat(parametersLegacy0.hashCode()).isEqualTo(parametersLegacy1.hashCode());
  }

  @Test
  public void testNotEqualAndNotEqualHashCode_noPrefix() throws Exception {
    Ed25519Parameters parametersNoPrefix = Ed25519Parameters.create();

    Ed25519Parameters parametersTink = Ed25519Parameters.create(TINK);
    Ed25519Parameters parametersCrunchy = Ed25519Parameters.create(CRUNCHY);
    Ed25519Parameters parametersLegacy = Ed25519Parameters.create(LEGACY);

    assertThat(parametersNoPrefix).isNotEqualTo(parametersTink);
    assertThat(parametersNoPrefix.hashCode()).isNotEqualTo(parametersTink.hashCode());

    assertThat(parametersNoPrefix).isNotEqualTo(parametersCrunchy);
    assertThat(parametersNoPrefix.hashCode()).isNotEqualTo(parametersCrunchy.hashCode());

    assertThat(parametersNoPrefix).isNotEqualTo(parametersLegacy);
    assertThat(parametersNoPrefix.hashCode()).isNotEqualTo(parametersLegacy.hashCode());
  }

  @Test
  public void testNotEqualAndNotEqualHashCode_tink() throws Exception {
    Ed25519Parameters parametersTink = Ed25519Parameters.create(TINK);

    Ed25519Parameters parametersCrunchy = Ed25519Parameters.create(CRUNCHY);
    Ed25519Parameters parametersLegacy = Ed25519Parameters.create(LEGACY);

    assertThat(parametersTink).isNotEqualTo(parametersCrunchy);
    assertThat(parametersTink.hashCode()).isNotEqualTo(parametersCrunchy.hashCode());

    assertThat(parametersTink).isNotEqualTo(parametersLegacy);
    assertThat(parametersTink.hashCode()).isNotEqualTo(parametersLegacy.hashCode());
  }

  @Test
  public void testNotEqualAndNotEqualHashCode_crunchy_legacy() throws Exception {
    Ed25519Parameters parametersCrunchy = Ed25519Parameters.create(CRUNCHY);
    Ed25519Parameters parametersLegacy = Ed25519Parameters.create(LEGACY);

    assertThat(parametersCrunchy).isNotEqualTo(parametersLegacy);
    assertThat(parametersCrunchy.hashCode()).isNotEqualTo(parametersLegacy.hashCode());
  }
}
