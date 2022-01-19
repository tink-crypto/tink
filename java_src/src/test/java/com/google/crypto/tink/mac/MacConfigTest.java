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

package com.google.crypto.tink.mac;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Mac;
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
 * Tests for MacConfig. Using FixedMethodOrder to ensure that aaaTestInitialization runs first, as
 * it tests execution of a static block within MacConfig-class.
 */
@RunWith(JUnit4.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class MacConfigTest {

  // This test must run first.
  @Test
  public void aaaTestInitialization() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> Registry.getCatalogue("tinkmac"));
    assertThat(e.toString()).contains("no catalogue found");
    assertThat(e.toString()).contains("MacConfig.register()");
    String typeUrl = "type.googleapis.com/google.crypto.tink.HmacKey";
    e = assertThrows(GeneralSecurityException.class, () -> Registry.getKeyManager(typeUrl));
    assertThat(e.toString()).contains("No key manager found");

    // Initialize the config.
    MacConfig.register();

    // After registration the key manager should be present.
    Registry.getKeyManager(typeUrl);

    // Running init() manually again should succeed.
    MacConfig.register();
  }

  @Test
  public void testNoFipsRegister() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    // Register MAC key manager.
    MacConfig.register();

    // Check if all key types are registered when not using FIPS mode.
    String[] keyTypeUrls = {
      "type.googleapis.com/google.crypto.tink.HmacKey",
      "type.googleapis.com/google.crypto.tink.AesCmacKey",
    };

    for (String typeUrl : keyTypeUrls) {
      Registry.getKeyManager(typeUrl, Mac.class);
    }
  }

  @Test
  public void testFipsRegisterFipsKeys() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());
    Assume.assumeTrue(TinkFipsUtil.fipsModuleAvailable());

    // Register MAC key manager.
    MacConfig.register();

    String[] keyTypeUrls = {
      "type.googleapis.com/google.crypto.tink.HmacKey",
    };

    for (String typeUrl : keyTypeUrls) {
      Registry.getKeyManager(typeUrl, Mac.class);
    }
  }

  @Test
  public void testFipsRegisterNonFipsKeys() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());
    Assume.assumeTrue(TinkFipsUtil.fipsModuleAvailable());

    // Register MAC key manager.
    MacConfig.register();

    // List of algorithms which are not part of FIPS and should not be registered.
    String[] keyTypeUrls = {
      "type.googleapis.com/google.crypto.tink.AesCmacKey",
    };

    for (String typeUrl : keyTypeUrls) {
      GeneralSecurityException e =
          assertThrows(
              GeneralSecurityException.class, () -> Registry.getUntypedKeyManager(typeUrl));
      assertThat(e.toString()).contains("No key manager found");
    }
  }
}
