// Copyright 2022 Google Inc.
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

package com.google.crypto.tink.prf;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Registry;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import java.security.GeneralSecurityException;
import org.junit.Assume;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.junit.runners.MethodSorters;

/**
 * Tests for PrfConfig. Using FixedMethodOrder to ensure that aaaTestInitialization runs first, as
 * it tests execution of a static block within AeadConfig-class.
 */
@RunWith(JUnit4.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class PrfConfigTest {
  // This test must run first.
  @Test
  public void aaaTestInitialization() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    // Before registration, the key manager should be absent.
    String typeUrl = "type.googleapis.com/google.crypto.tink.HkdfPrfKey";
    assertThrows(GeneralSecurityException.class, () -> Registry.getUntypedKeyManager(typeUrl));

    // Initialize the config.
    PrfConfig.register();

    // After registration, the key manager should be present.
    Registry.getKeyManager(typeUrl, Prf.class);

    // Running init() manually again should succeed.
    PrfConfig.register();
  }

  @Test
  public void testNoFipsRegister() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    // Register Prf key manager
    PrfConfig.register();

    // Check if all key types are registered when not using FIPS mode.
    String[] keyTypeUrls = {
      "type.googleapis.com/google.crypto.tink.HmacPrfKey",
      "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
      "type.googleapis.com/google.crypto.tink.AesCmacPrfKey",
    };

    for (String typeUrl : keyTypeUrls) {
      Registry.getKeyManager(typeUrl, Prf.class);
    }
  }

  @Test
  public void testFipsRegisterFipsKeys() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());
    Assume.assumeTrue(TinkFipsUtil.fipsModuleAvailable());

    // Register Prf key manager
    PrfConfig.register();

    String[] keyTypeUrls = {
      "type.googleapis.com/google.crypto.tink.HmacPrfKey",
    };

    for (String typeUrl : keyTypeUrls) {
      Registry.getKeyManager(typeUrl, Prf.class);
    }
  }

  @Test
  public void testFipsRegisterNonFipsKeys() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());
    Assume.assumeTrue(TinkFipsUtil.fipsModuleAvailable());

    // Register Prf key manager
    PrfConfig.register();

    // List of algorithms which are not part of FIPS and should not be registered.
    String[] keyTypeUrls = {
      "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
      "type.googleapis.com/google.crypto.tink.AesCmacPrfKey",
    };

    for (String typeUrl : keyTypeUrls) {
      GeneralSecurityException e =
          assertThrows(
              GeneralSecurityException.class, () -> Registry.getUntypedKeyManager(typeUrl));
      assertThat(e.toString()).contains("No key manager found");
    }
  }
}
