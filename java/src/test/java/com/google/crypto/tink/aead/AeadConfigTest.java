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

package com.google.crypto.tink.aead;

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
 * Tests for AeadConfig. Using FixedMethodOrder to ensure that aaaTestInitialization runs first, as
 * it tests execution of a static block within AeadConfig-class.
 */
@RunWith(JUnit4.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AeadConfigTest {

  // This test must run first.
  @Test
  public void aaaTestInitialization() throws Exception {
    try {
      Registry.getCatalogue("tinkmac");
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("no catalogue found");
      assertThat(e.toString()).contains("MacConfig.init()");
    }
    try {
      Registry.getCatalogue("tinkaead");
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("no catalogue found");
      assertThat(e.toString()).contains("AeadConfig.init()");
    }
    // Get the config proto, now the catalogues should be present,
    // as init() was triggered by a static block.
    RegistryConfig unused = AeadConfig.TINK_1_1_0;
    Registry.getCatalogue("tinkmac");
    Registry.getCatalogue("tinkaead");

    // Running init() manually again should succeed.
    AeadConfig.init();
  }

  @Test
  public void testConfigContents1_0_0() throws Exception {
    RegistryConfig config = AeadConfig.TINK_1_0_0;
    assertEquals(7, config.getEntryCount());
    assertEquals("TINK_AEAD_1_0_0", config.getConfigName());

    TestUtil.verifyConfigEntry(
        config.getEntry(0),
        "TinkMac",
        "Mac",
        "type.googleapis.com/google.crypto.tink.HmacKey",
        true,
        0);
    TestUtil.verifyConfigEntry(
        config.getEntry(1),
        "TinkAead",
        "Aead",
        "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
        true,
        0);
    TestUtil.verifyConfigEntry(
        config.getEntry(2),
        "TinkAead",
        "Aead",
        "type.googleapis.com/google.crypto.tink.AesEaxKey",
        true,
        0);
    TestUtil.verifyConfigEntry(
        config.getEntry(3),
        "TinkAead",
        "Aead",
        "type.googleapis.com/google.crypto.tink.AesGcmKey",
        true,
        0);
    TestUtil.verifyConfigEntry(
        config.getEntry(4),
        "TinkAead",
        "Aead",
        "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key",
        true,
        0);
    TestUtil.verifyConfigEntry(
        config.getEntry(5),
        "TinkAead",
        "Aead",
        "type.googleapis.com/google.crypto.tink.KmsAeadKey",
        true,
        0);
    TestUtil.verifyConfigEntry(
        config.getEntry(6),
        "TinkAead",
        "Aead",
        "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey",
        true,
        0);
  }

  @Test
  public void testConfigContents1_1_0() throws Exception {
    RegistryConfig config = AeadConfig.TINK_1_1_0;
    assertEquals(7, config.getEntryCount());
    assertEquals("TINK_AEAD_1_1_0", config.getConfigName());

    TestUtil.verifyConfigEntry(
        config.getEntry(0),
        "TinkMac",
        "Mac",
        "type.googleapis.com/google.crypto.tink.HmacKey",
        true,
        0);
    TestUtil.verifyConfigEntry(
        config.getEntry(1),
        "TinkAead",
        "Aead",
        "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
        true,
        0);
    TestUtil.verifyConfigEntry(
        config.getEntry(2),
        "TinkAead",
        "Aead",
        "type.googleapis.com/google.crypto.tink.AesEaxKey",
        true,
        0);
    TestUtil.verifyConfigEntry(
        config.getEntry(3),
        "TinkAead",
        "Aead",
        "type.googleapis.com/google.crypto.tink.AesGcmKey",
        true,
        0);
    TestUtil.verifyConfigEntry(
        config.getEntry(4),
        "TinkAead",
        "Aead",
        "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key",
        true,
        0);
    TestUtil.verifyConfigEntry(
        config.getEntry(5),
        "TinkAead",
        "Aead",
        "type.googleapis.com/google.crypto.tink.KmsAeadKey",
        true,
        0);
    TestUtil.verifyConfigEntry(
        config.getEntry(6),
        "TinkAead",
        "Aead",
        "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey",
        true,
        0);
  }

  @Test
  public void testRegistration() throws Exception {
    String typeUrl = "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";
    try {
      Registry.getKeyManager(typeUrl);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("No key manager found");
    }
    // After registration the key manager should be present.
    Config.register(AeadConfig.TINK_1_1_0);
    Registry.getKeyManager(typeUrl);
  }
}
