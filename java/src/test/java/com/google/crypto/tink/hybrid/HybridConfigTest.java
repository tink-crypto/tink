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

package com.google.crypto.tink.hybrid;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.fail;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.Registry;
import java.security.GeneralSecurityException;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.junit.runners.MethodSorters;

/**
 * Tests for HybridConfig. Using FixedMethodOrder to ensure that aaaTestInitialization runs first,
 * as it tests execution of a static block within HybridConfig-class.
 */
@RunWith(JUnit4.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class HybridConfigTest {

  // This test must run first.
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
      Registry.getCatalogue("tinkhybridencrypt");
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("no catalogue found");
      assertThat(e.toString()).contains("HybridConfig.register()");
    }
    try {
      Registry.getCatalogue("tinkhybriddecrypt");
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("no catalogue found");
      assertThat(e.toString()).contains("HybridConfig.register()");
    }

    String typeUrl = "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
    try {
      Registry.getUntypedKeyManager(typeUrl);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("No key manager found");
    }

    // Initialize the config.
    HybridConfig.register();

    Registry.getKeyManager(typeUrl, HybridDecrypt.class);

    // Running init() manually again should succeed.
    HybridConfig.register();
  }
}
