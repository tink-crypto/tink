// Copyright 2021 Google LLC
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
package com.google.crypto.tink.config.internal;

import static com.google.common.truth.Truth.assertThat;

import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for TinkFipsUtil. The tests here check the behavior of Tink when built with or without the
 * --use_only_fips flag. In order to get complete coverage a build should be tested with: 1) Build
 * without the --use_only_fips flag. 2) Build with the --use_only_fips flag, and BoringCrypto not
 * being available. 3) Build with the --use_only_fips flag, and BoringCrypto being available.
 */
@RunWith(JUnit4.class)
public final class TinkFipsUtilTest {

  @Test
  public void testFipsOnlyModeDisabledAlgorithmCompatibility() {
    // Test behavior when FIPS-only mode is not used.
    Assume.assumeFalse(TinkFipsStatus.useOnlyFips());
    assertThat(TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS.isCompatible()).isTrue();
    assertThat(TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO.isCompatible())
        .isTrue();
  }

  @Test
  public void testFipsOnlyModeEnabledAlgorithmCompatibility() {
    // Test behavior when FIPS-only mode is used.
    Assume.assumeTrue(TinkFipsStatus.useOnlyFips());
    assertThat(TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS.isCompatible()).isFalse();

    // BoringCrypto is available, therefore an algorithm which has a FIPS validated
    // implementation is compatible.
    Assume.assumeTrue(TinkFipsStatus.fipsModuleAvailable());
    assertThat(TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO.isCompatible())
        .isTrue();
  }

  @Test
  public void testFipsOnlyModeEnabledAlgorithmCompatibilityNoBoringCrypto() {
    // Test behavior when FIPS-only mode is used.
    Assume.assumeTrue(TinkFipsStatus.useOnlyFips());
    assertThat(TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS.isCompatible()).isFalse();

    // BoringCrypto is not available, therefore no validated implementation is available and
    // the compatibility check must fail.
    Assume.assumeTrue(!TinkFipsStatus.fipsModuleAvailable());
    assertThat(TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO.isCompatible())
        .isFalse();
  }
}
