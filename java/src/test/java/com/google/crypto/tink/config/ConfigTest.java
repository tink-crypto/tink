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

package com.google.crypto.tink.config;

import static org.junit.Assert.fail;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.aead.AesEaxKeyManager;
import com.google.crypto.tink.proto.KeyTypeEntry;
import com.google.crypto.tink.proto.TinkConfig;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for Config.
 */
@RunWith(JUnit4.class)
public class ConfigTest {

  @Test
  public void testSingleKeyTypeEntry() throws Exception {
    Registry.reset();
    String typeUrl = AesEaxKeyManager.TYPE_URL;
    KeyTypeEntry entry = KeyTypeEntry.newBuilder()
        .setTypeUrl(typeUrl)
        .setPrimitiveName("Aead")
        .setCatalogueName("Tink")
        .setKeyManagerVersion(0)
        .setNewKeyAllowed(true)
        .build();
    try {
      KeyManager<Aead> unused = Registry.getKeyManager(typeUrl);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }

    Config.registerKeyType(entry);
    KeyManager<Aead> unused = Registry.getKeyManager(typeUrl);
  }

  @Test
  public void testRegistrationOfRelease1Configs() throws Exception {
    TinkConfig[] configs = new TinkConfig[9];
    configs[0] = Config.TINK_1_0_0;
    configs[1] = Config.TINK_MAC_1_0_0;
    configs[2] = Config.TINK_AEAD_1_0_0;
    configs[3] = Config.TINK_HYBRID_1_0_0;
    configs[4] = Config.TINK_HYBRID_ENCRYPT_1_0_0;
    configs[5] = Config.TINK_HYBRID_DECRYPT_1_0_0;
    configs[6] = Config.TINK_SIGNATURE_1_0_0;
    configs[7] = Config.TINK_SIGNATURE_SIGN_1_0_0;
    configs[8] = Config.TINK_SIGNATURE_VERIFY_1_0_0;
    for (TinkConfig tinkConfig : configs) {
      Registry.reset();
      // Initially, there should be no key manager in the registry.
      for (KeyTypeEntry entry : tinkConfig.getEntryList()) {
        try {
          KeyManager<?> unused = Registry.getKeyManager(entry.getTypeUrl());
          fail("Registry should contain no manager for " + entry.getTypeUrl());
        } catch (GeneralSecurityException e) {
          // expected
        }
      }
      // After registering the config the registry should contain the key managers.
      Config.register(tinkConfig);
      for (KeyTypeEntry entry : tinkConfig.getEntryList()) {
        KeyManager<?> unused = Registry.getKeyManager(entry.getTypeUrl());
      }
      // Another register-attmpt should fail, as key managers already exist.
      try {
        Config.register(tinkConfig);
        fail("Repeated registration of the same config should have thrown exception.");
      } catch (GeneralSecurityException e) {
        // expected
      }
    }
  }
}
