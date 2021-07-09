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
package com.google.crypto.tink.config;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.config.internal.TinkFipsUtil;
import java.security.GeneralSecurityException;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for TinkFips. The tests here check the behavior of Tink when built with or without the
 * --use_only_fips flag. In order to get complete coverage a build should be tested with: 1) Build
 * without the --use_only_fips flag. 2) Build with the --use_only_fips flag, and BoringCrypto not
 * being available. 3) Build with the --use_only_fips flag, and BoringCrypto being available.
 */
@RunWith(JUnit4.class)
public final class TinkFipsTest {

  @Test
  public void testFipsOnlyModeConsistentDisabled() {
    // If the TinkFipsUtil reports that FIPS-mode is disabled, then TinkFips must report that
    // FIPS-mode is disabled.
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    assertThat(TinkFips.useOnlyFips()).isFalse();
  }

  @Test
  public void testFipsOnlyModeConsistentEnabled() {
    // If the TinkFipsUtil reports that FIPS-mode is enabled, then TinkFips must report that
    // FIPS-mode is enabled.
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());
    assertThat(TinkFips.useOnlyFips()).isTrue();
  }

  @Test
  public void testFipsEnablingAtRuntime() throws GeneralSecurityException {
    // If Tink has not been built in FIPS-mode, then the useOnlyFips() call should only return
    // true after the restrictions have been enabled.
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    assertThat(TinkFips.useOnlyFips()).isFalse();
    TinkFips.restrictToFips();
    assertThat(TinkFips.useOnlyFips()).isTrue();
  }

}
