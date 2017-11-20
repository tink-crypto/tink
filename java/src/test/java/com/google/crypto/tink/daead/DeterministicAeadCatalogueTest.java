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

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.proto.KeyTypeEntry;
import com.google.crypto.tink.proto.RegistryConfig;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for DeterministicAeadCatalogue. */
@RunWith(JUnit4.class)
public class DeterministicAeadCatalogueTest {

  @Test
  public void testBasic() throws Exception {
    DeterministicAeadCatalogue catalogue = new DeterministicAeadCatalogue();

    // Check a single key type, incl. case-insensitve primitive name.
    String keyType = "type.googleapis.com/google.crypto.tink.AesSivKey";
    {
      KeyManager<DeterministicAead> manager =
          catalogue.getKeyManager(keyType, "DeterministicAead", 0);
      assertThat(manager.doesSupport(keyType)).isTrue();
    }
    {
      KeyManager<DeterministicAead> manager =
          catalogue.getKeyManager(keyType, "DeterministicAEaD", 0);
      assertThat(manager.doesSupport(keyType)).isTrue();
    }
    {
      KeyManager<DeterministicAead> manager =
          catalogue.getKeyManager(keyType, "dEtermInisticaeAD", 0);
      assertThat(manager.doesSupport(keyType)).isTrue();
    }

    // Check all entries from the current DeterministicAeadConfig.
    RegistryConfig config = DeterministicAeadConfig.TINK_1_1_0;
    int count = 0;
    for (KeyTypeEntry entry : config.getEntryList()) {
      if ("DeterministicAead".equals(entry.getPrimitiveName())) {
        count = count + 1;
        KeyManager<DeterministicAead> manager =
            catalogue.getKeyManager(
                entry.getTypeUrl(), "deterministicaead", entry.getKeyManagerVersion());
        assertThat(manager.doesSupport(entry.getTypeUrl())).isTrue();
      }
    }
    assertEquals(1, count);
  }

  @Test
  public void testErrors() throws Exception {
    DeterministicAeadCatalogue catalogue = new DeterministicAeadCatalogue();
    String keyType = "type.googleapis.com/google.crypto.tink.AesSivKey";

    // Wrong primitive name.
    try {
      catalogue.getKeyManager(keyType, "mac", 0);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("No support for primitive");
    }

    // Wrong key manager version.
    try {
      catalogue.getKeyManager(keyType, "deterministicaead", 1);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("No key manager");
      assertThat(e.toString()).contains("version at least");
    }

    // Wrong key type.
    try {
      catalogue.getKeyManager("some.unknown.key.type", "deterministicaead", 0);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("No support for primitive");
      assertThat(e.toString()).contains("with key type");
    }
  }
}
