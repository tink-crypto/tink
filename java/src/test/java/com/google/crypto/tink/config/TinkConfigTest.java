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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.fail;

import com.google.crypto.tink.Config;
import com.google.crypto.tink.Registry;
import java.security.GeneralSecurityException;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.junit.runners.MethodSorters;

/**
 * Tests for TinkConfig. Using FixedMethodOrder to ensure that aaaTestInitialization runs first, as
 * it tests execution of a static block within referenced Config-classes.
 */
@RunWith(JUnit4.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class TinkConfigTest {
  @Test
  public void aaaTestInitialization() throws Exception {
    try {
      Registry.getCatalogue("tinkmac");
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("no catalogue found");
      assertThat(e.toString()).contains("MacConfig.register()");
    }
    try {
      Registry.getCatalogue("tinkaead");
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("no catalogue found");
      assertThat(e.toString()).contains("AeadConfig.register()");
    }
    try {
      Registry.getCatalogue("tinkhybriddecrypt");
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("no catalogue found");
      assertThat(e.toString()).contains("HybridConfig.register()");
    }
    try {
      Registry.getCatalogue("tinkhybridencrypt");
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("no catalogue found");
      assertThat(e.toString()).contains("HybridConfig.register()");
    }
    try {
      Registry.getCatalogue("tinkpublickeysign");
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("no catalogue found");
      assertThat(e.toString()).contains("SignatureConfig.register()");
    }
    try {
      Registry.getCatalogue("tinkpublickeyverify");
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("no catalogue found");
      assertThat(e.toString()).contains("SignatureConfig.register()");
    }

    String macTypeUrl = "type.googleapis.com/google.crypto.tink.HmacKey";
    String aeadTypeUrl = "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";
    String daeadTypeUrl = "type.googleapis.com/google.crypto.tink.AesSivKey";
    String hybridTypeUrl = "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
    String signTypeUrl = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";
    String streamingAeadTypeUrl = "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey";
    try {
      Registry.getUntypedKeyManager(macTypeUrl);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("No key manager found");
    }
    try {
      Registry.getUntypedKeyManager(aeadTypeUrl);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("No key manager found");
    }
    try {
      Registry.getUntypedKeyManager(daeadTypeUrl);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("No key manager found");
    }
    try {
      Registry.getUntypedKeyManager(hybridTypeUrl);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("No key manager found");
    }
    try {
      Registry.getUntypedKeyManager(signTypeUrl);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("No key manager found");
    }
    try {
      Registry.getUntypedKeyManager(streamingAeadTypeUrl);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("No key manager found");
    }

    // Initialize the config.
    TinkConfig.register();

    // After registration the key managers should be present.
    Config.register(TinkConfig.TINK_1_1_0);
    Registry.getUntypedKeyManager(macTypeUrl);
    Registry.getUntypedKeyManager(aeadTypeUrl);
    Registry.getUntypedKeyManager(daeadTypeUrl);
    Registry.getUntypedKeyManager(hybridTypeUrl);
    Registry.getUntypedKeyManager(signTypeUrl);
    Registry.getUntypedKeyManager(streamingAeadTypeUrl);
  }
}
