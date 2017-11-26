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

package com.google.crypto.tink.signature;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.proto.KeyTypeEntry;
import com.google.crypto.tink.proto.RegistryConfig;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for PublicKeySignCatalogue. */
@RunWith(JUnit4.class)
public class PublicKeySignCatalogueTest {

  @Test
  public void testBasic() throws Exception {
    PublicKeySignCatalogue catalogue = new PublicKeySignCatalogue();

    // Check a single key type for signing, incl. case-insensitve primitive name.
    String keyType = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";
    {
      KeyManager<PublicKeySign> manager = catalogue.getKeyManager(keyType, "PublicKeySign", 0);
      assertThat(manager.doesSupport(keyType)).isTrue();
    }
    {
      KeyManager<PublicKeySign> manager = catalogue.getKeyManager(keyType, "PUBLicKeYSigN", 0);
      assertThat(manager.doesSupport(keyType)).isTrue();
    }
    {
      KeyManager<PublicKeySign> manager = catalogue.getKeyManager(keyType, "PUBLICKEYSIGN", 0);
      assertThat(manager.doesSupport(keyType)).isTrue();
    }

    // Check all entries from the current SignatureConfig.
    RegistryConfig config = SignatureConfig.TINK_1_0_0;
    int count = 0;
    for (KeyTypeEntry entry : config.getEntryList()) {
      if ("PublicKeySign".equals(entry.getPrimitiveName())) {
        count = count + 1;
        KeyManager<PublicKeySign> manager =
            catalogue.getKeyManager(
                entry.getTypeUrl(), "publickeysign", entry.getKeyManagerVersion());
        assertThat(manager.doesSupport(entry.getTypeUrl())).isTrue();
      }
    }
    assertEquals(2, count);
  }

  @Test
  public void testErrors() throws Exception {
    PublicKeySignCatalogue catalogue = new PublicKeySignCatalogue();
    String keyType = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";

    // Wrong primitive name.
    try {
      catalogue.getKeyManager(keyType, "aead", 0);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("No support for primitive");
    }

    // Wrong key manager version.
    try {
      catalogue.getKeyManager(keyType, "publickeysign", 1);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("No key manager");
      assertThat(e.toString()).contains("version at least");
    }

    // Wrong key type.
    try {
      catalogue.getKeyManager("some.unknown.key.type", "publickeysign", 0);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("No support for primitive");
      assertThat(e.toString()).contains("with key type");
    }
  }
}
