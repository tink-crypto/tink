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

package com.google.crypto.tink;

import static org.junit.Assert.fail;

import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AesEaxKeyManager;
import com.google.crypto.tink.hybrid.HybridConfig;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.proto.KeyTypeEntry;
import com.google.crypto.tink.proto.RegistryConfig;
import com.google.crypto.tink.signature.SignatureConfig;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for Config.
 */
@RunWith(JUnit4.class)
public class ConfigTest {
  private RegistryConfig createAeadConfig() {
    return RegistryConfig.newBuilder()
        .addEntry(Config.getTinkKeyTypeEntry(
            "TinkAead", "Aead", "AesEaxKey", 0, true))
        .setConfigName("TINK_AEAD_1_0_0")
        .build();
  }

  private RegistryConfig createMacConfig() {
    return RegistryConfig.newBuilder()
        .addEntry(Config.getTinkKeyTypeEntry(
            "TinkMac", "Mac", "HmacKey", 0, true))
        .setConfigName("TINK_MAC_1_0_0")
        .build();
  }

  private RegistryConfig createHybridConfig() {
    return RegistryConfig.newBuilder()
        .addEntry(Config.getTinkKeyTypeEntry(
            "TinkHybrid", "HybridDecrypt", "EciesAeadHkdfPrivateKey", 0, true))
        .addEntry(Config.getTinkKeyTypeEntry(
            "TinkHybrid", "HybridEncrypt", "EciesAeadHkdfPublicKey", 0, true))
        .setConfigName("TINK_HYBRID_1_0_0")
        .build();
  }

  private RegistryConfig createSignatureConfig() {
    return RegistryConfig.newBuilder()
        .addEntry(Config.getTinkKeyTypeEntry(
            "TinkSignature", "PublicKeySign", "EcdsaPrivateKey", 0, true))
        .addEntry(Config.getTinkKeyTypeEntry(
            "TinkSignature", "PublicKeyVerify", "Ed25519PublicKey", 0, true))
        .build();
  }

  @Test
  public void testRegisterKeyType_NoCatalogue_shouldThrowException() throws Exception {
    Registry.reset();
    String typeUrl = AesEaxKeyManager.TYPE_URL;
    KeyTypeEntry entry = KeyTypeEntry.newBuilder()
        .setTypeUrl(typeUrl)
        .setPrimitiveName("Aead")
        .setCatalogueName("TinkAead")
        .setKeyManagerVersion(0)
        .setNewKeyAllowed(true)
        .build();

    try {
      Config.registerKeyType(entry);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  private void testRegister_NoCatalogue_shouldThrowException(RegistryConfig config)
      throws Exception {
    try {
      Config.register(config);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void testRegister_NoCatalogue_shouldThrowException() throws Exception {
    Registry.reset();
    testRegister_NoCatalogue_shouldThrowException(createAeadConfig());
    testRegister_NoCatalogue_shouldThrowException(createMacConfig());
    testRegister_NoCatalogue_shouldThrowException(createHybridConfig());
    testRegister_NoCatalogue_shouldThrowException(createSignatureConfig());
  }

  @Test
  public void testRegister_WithInit_shouldWork() throws Exception {
    Registry.reset();
    // The registry is empty, register should fail.
    testRegister_NoCatalogue_shouldThrowException(createAeadConfig());
    testRegister_NoCatalogue_shouldThrowException(createMacConfig());
    testRegister_NoCatalogue_shouldThrowException(createHybridConfig());

    // Fill the registry with Aead key managers.
    AeadConfig.init();
    // Now register for Aead and Mac should succeed.
    Config.register(createAeadConfig());
    Config.register(createMacConfig());
    // But hybrid still fail.
    testRegister_NoCatalogue_shouldThrowException(createHybridConfig());
    HybridConfig.init();
    // Hybrid should work now.
    Config.register(createHybridConfig());
  }

  @Test
  public void testRegister_Tink_1_0_0_shouldWork() throws Exception {
    Registry.reset();
    RegistryConfig[] configs = new RegistryConfig[4];
    configs[0] = AeadConfig.TINK_1_0_0;
    configs[1] = HybridConfig.TINK_1_0_0;
    configs[2] = MacConfig.TINK_1_0_0;
    configs[3] = SignatureConfig.TINK_1_0_0;
    for (RegistryConfig tinkConfig : configs) {
      // After registering the config the registry should contain the key managers.
      Config.register(tinkConfig);
      for (KeyTypeEntry entry : tinkConfig.getEntryList()) {
        KeyManager<?> unused = Registry.getKeyManager(entry.getTypeUrl());
      }

      // Another register-attempt should still work, because the key managers are the same.
      try {
        Config.register(tinkConfig);
      } catch (GeneralSecurityException e) {
        fail("Repeated registration of the same config should work.");
      }
    }
  }
}
