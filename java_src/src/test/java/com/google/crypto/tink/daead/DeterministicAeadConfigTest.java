// Copyright 2017 Google Inc.
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

package com.google.crypto.tink.daead;

import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.config.TinkFips;
import java.security.GeneralSecurityException;
import org.junit.Assume;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.junit.runners.MethodSorters;

/**
 * Tests for DeterministicAeadConfig. Using FixedMethodOrder to ensure that aaaTestInitialization
 * runs first, as it tests execution of a static block within DeterministicAeadConfig-class.
 */
@RunWith(JUnit4.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DeterministicAeadConfigTest {

  // This test must run first.
  @Test
  public void aaaTestInitialization() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());
    assertThrows(
        GeneralSecurityException.class, () -> Registry.getCatalogue("tinkdeterministicaead"));

    // Before registration, the key manager should be absent.
    String typeUrl = "type.googleapis.com/google.crypto.tink.AesSivKey";
    assertThrows(GeneralSecurityException.class, () -> Registry.getUntypedKeyManager(typeUrl));

    // Initialize the config.
    DeterministicAeadConfig.register();

    // After registration, the key manager should be present.
    Registry.getKeyManager(typeUrl, DeterministicAead.class);

    // Running init() manually again should succeed.
    DeterministicAeadConfig.register();
  }

  @Test
  public void testNoFipsRegister() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    // Register AEAD key manager
    DeterministicAeadConfig.register();

    // Check if all key types are registered when not using FIPS mode.
    String[] keyTypeUrls = {
      "type.googleapis.com/google.crypto.tink.AesSivKey",
    };

    for (String typeUrl : keyTypeUrls) {
      Registry.getKeyManager(typeUrl, DeterministicAead.class);
    }
  }

  @Test
  public void testFipsRegisterNonFipsKeys() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());

    // Register AEAD key manager
    DeterministicAeadConfig.register();

    // List of algorithms which are not part of FIPS and should not be registered.
    String[] keyTypeUrls = {
      "type.googleapis.com/google.crypto.tink.AesSivKey",
    };

    for (String typeUrl : keyTypeUrls) {
      assertThrows(GeneralSecurityException.class, () -> Registry.getUntypedKeyManager(typeUrl));
    }
  }
}
