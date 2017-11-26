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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.proto.KeyTypeEntry;
import com.google.crypto.tink.proto.RegistryConfig;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for HybridDecryptCatalogue. */
@RunWith(JUnit4.class)
public class HybridDecryptCatalogueTest {

  @Test
  public void testBasic() throws Exception {
    HybridDecryptCatalogue catalogue = new HybridDecryptCatalogue();

    // Check a single key type for decryption, incl. case-insensitve primitive name.
    String keyType = "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
    {
      KeyManager<HybridDecrypt> manager = catalogue.getKeyManager(keyType, "HybridDecrypt", 0);
      assertThat(manager.doesSupport(keyType)).isTrue();
    }
    {
      KeyManager<HybridDecrypt> manager = catalogue.getKeyManager(keyType, "HyBRidDeCRYPt", 0);
      assertThat(manager.doesSupport(keyType)).isTrue();
    }
    {
      KeyManager<HybridDecrypt> manager = catalogue.getKeyManager(keyType, "HYBRIDDecRYPT", 0);
      assertThat(manager.doesSupport(keyType)).isTrue();
    }

    // Check all entries from the current HybridConfig.
    RegistryConfig config = HybridConfig.TINK_1_0_0;
    int count = 0;
    for (KeyTypeEntry entry : config.getEntryList()) {
      if ("HybridDecrypt".equals(entry.getPrimitiveName())) {
        count = count + 1;
        KeyManager<HybridDecrypt> manager =
            catalogue.getKeyManager(
                entry.getTypeUrl(), "hybriddecrypt", entry.getKeyManagerVersion());
        assertThat(manager.doesSupport(entry.getTypeUrl())).isTrue();
      }
    }
    assertEquals(1, count);
  }

  @Test
  public void testErrors() throws Exception {
    HybridDecryptCatalogue catalogue = new HybridDecryptCatalogue();
    String keyType = "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";

    // Wrong primitive name.
    try {
      catalogue.getKeyManager(keyType, "aead", 0);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("No support for primitive");
    }

    // Wrong key manager version.
    try {
      catalogue.getKeyManager(keyType, "hybriddecrypt", 1);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("No key manager");
      assertThat(e.toString()).contains("version at least");
    }

    // Wrong key type.
    try {
      catalogue.getKeyManager("some.unknown.key.type", "hybriddecrypt", 0);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("No support for primitive");
      assertThat(e.toString()).contains("with key type");
    }
  }
}
