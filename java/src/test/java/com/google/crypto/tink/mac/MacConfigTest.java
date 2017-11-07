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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.Catalogue;
import com.google.crypto.tink.Config;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.Mac;
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
 * Tests for MacConfig.
 * Using FixedMethodOrder to ensure that aaaTestInitialization runs first,
 * as it tests execution of a static block within MacConfig-class.
 */
@RunWith(JUnit4.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class MacConfigTest {

  // This test must run first.
  @Test
  public void aaaTestInitialization() throws Exception {
    try {
      Catalogue catalogue = Registry.getCatalogue("tinkmac");
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("no catalogue found");
      assertThat(e.toString()).contains("MacConfig.init()");
    }
    // Get the config proto, now the catalogues should be present,
    // as init() was triggered by a static block.
    RegistryConfig config = MacConfig.TINK_1_0_0;
    Catalogue catalogue = Registry.getCatalogue("tinkmac");
    catalogue = Registry.getCatalogue("tinkmac");

    // Running init() manually again should succeed.
    MacConfig.init();
  }

  @Test
  public void testConfigContents() throws Exception {
    RegistryConfig config = MacConfig.TINK_1_0_0;
    assertEquals(1, config.getEntryCount());
    assertEquals("TINK_MAC_1_0_0", config.getConfigName());

    TestUtil.verifyConfigEntry(config.getEntry(0),
        "TinkMac", "Mac", "type.googleapis.com/google.crypto.tink.HmacKey", true, 0);
  }

  @Test
  public void testRegistration() throws Exception {
    String typeUrl = "type.googleapis.com/google.crypto.tink.HmacKey";
    try {
      KeyManager<Mac> manager = Registry.getKeyManager(typeUrl);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("No key manager found");
    }
    // After registration the key manager should be present.
    Config.register(MacConfig.TINK_1_0_0);
    KeyManager<Mac> manager = Registry.getKeyManager(typeUrl);
  }
}
