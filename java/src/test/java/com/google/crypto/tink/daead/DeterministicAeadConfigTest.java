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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.Config;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.proto.RegistryConfig;
import java.security.GeneralSecurityException;
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
    try {
      Registry.getCatalogue("tinkdeterministicaead");
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("no catalogue found");
      assertThat(e.toString()).contains("DeterministicAeadConfig.init()");
    }
    // Get the config proto, now the catalogues should be present,
    // as init() was triggered by a static block.
    RegistryConfig unused = DeterministicAeadConfig.TINK_1_1_0;
    Registry.getCatalogue("tinkdeterministicaead");

    // Running init() manually again should succeed.
    DeterministicAeadConfig.init();
  }

  @Test
  public void testConfigContents() throws Exception {
    RegistryConfig config = DeterministicAeadConfig.TINK_1_1_0;
    assertEquals(1, config.getEntryCount());
    assertEquals("TINK_DETERMINISTIC_AEAD_1_1_0", config.getConfigName());

    TestUtil.verifyConfigEntry(
        config.getEntry(0),
        "TinkDeterministicAead",
        "DeterministicAead",
        "type.googleapis.com/google.crypto.tink.AesSivKey",
        true,
        0);
  }

  @Test
  public void testRegistration() throws Exception {
    String typeUrl = "type.googleapis.com/google.crypto.tink.AesSivKey";
    try {
      Registry.getKeyManager(typeUrl);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("No key manager found");
    }
    // After registration the key manager should be present.
    Config.register(DeterministicAeadConfig.TINK_1_1_0);
    Registry.getKeyManager(typeUrl);
  }
}
