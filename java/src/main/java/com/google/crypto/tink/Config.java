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

import com.google.crypto.tink.proto.KeyTypeEntry;
import com.google.crypto.tink.proto.RegistryConfig;
import java.security.GeneralSecurityException;
import java.util.logging.Logger;

/**
 * Helper for handling of Tink configurations, i.e. of key types and
 * their corresponding key managers supported by a specific run-time
 * environment.
 *
 * <p>Configurations enable control of Tink setup via text-formatted
 * config files that determine which key types are supported, and
 * provide a mechanism for deprecation of obsolete/outdated
 * cryptographic schemes (see {@code config.proto} for more info).
 *
 * <p>Usage:
 *
 * <pre><code>
 * RegistryConfig registerConfig = ... // e.g. AeadConfig.TINK_1_0_0
 * Config.register(registerConfig);
 * </code></pre>
 */
public final class Config {
  private static final Logger logger = Logger.getLogger(Config.class.getName());

  public static KeyTypeEntry getTinkKeyTypeEntry(String catalogueName,
      String primitiveName, String keyProtoName, int keyManagerVersion,
      boolean newKeyAllowed) {
    return KeyTypeEntry.newBuilder()
        .setPrimitiveName(primitiveName)
        .setTypeUrl("type.googleapis.com/google.crypto.tink." + keyProtoName)
        .setKeyManagerVersion(keyManagerVersion)
        .setNewKeyAllowed(newKeyAllowed)
        .setCatalogueName(catalogueName)
        .build();
  }

  /**
   * Registers key managers according to the specification in {@code config}.
   */
  public static void register(RegistryConfig config) throws GeneralSecurityException {
    logger.info("Registering config " + config.getConfigName() + "...");
    for (KeyTypeEntry entry : config.getEntryList()) {
      registerKeyType(entry);
    }
    logger.info("Done registering config " + config.getConfigName() + ".");
  }

  /**
   * Registers a key manager according to the specification in {@code entry}.
   */
  @SuppressWarnings({"rawtypes", "unchecked"})
  public static void registerKeyType(KeyTypeEntry entry) throws GeneralSecurityException {
    validate(entry);
    Catalogue catalogue = Registry.getCatalogue(entry.getCatalogueName());
    KeyManager keyManager = catalogue.getKeyManager(
        entry.getTypeUrl(), entry.getPrimitiveName(), entry.getKeyManagerVersion());
    Registry.registerKeyManager(entry.getTypeUrl(), keyManager, entry.getNewKeyAllowed());
  }

  private static void validate(KeyTypeEntry entry) throws GeneralSecurityException {
    if (entry.getTypeUrl().isEmpty()) {
      throw new GeneralSecurityException("Missing type_url.");
    }
    if (entry.getPrimitiveName().isEmpty()) {
      throw new GeneralSecurityException("Missing primitive_name.");
    }
    if (entry.getCatalogueName().isEmpty()) {
      throw new GeneralSecurityException("Missing catalogue_name.");
    }
  }
}
