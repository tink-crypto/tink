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

/**
 * Static methods for handling of Tink configurations.
 *
 * <p>Configurations, i.e., a collection of key types and their corresponding key managers supported
 * by a specific run-time environment enable control of Tink setup via JSON-formatted config files
 * that determine which key types are supported, and provide a mechanism for deprecation of
 * obsolete/outdated cryptographic schemes (see <a
 * href="https://github.com/google/tink/blob/master/proto/config.proto">config.proto</a> for more
 * info).
 *
 * <h3>Usage</h3>
 *
 * <pre>{@code
 * RegistryConfig registryConfig = ...;
 * Config.register(registryConfig);
 * }</pre>
 *
 * @since 1.0.0
 */
public final class Config {
  /** Returns a {@link KeyTypeEntry} for Tink key types with the specified properties. */
  public static KeyTypeEntry getTinkKeyTypeEntry(
      String catalogueName,
      String primitiveName,
      String keyProtoName,
      int keyManagerVersion,
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
   * Tries to register key managers according to the specification in {@code config}.
   *
   * @throws GeneralSecurityException if cannot register this config with the {@link Registry}. This
   *     usually happens when either {@code config} contains any {@link KeyTypeEntry} that is
   *     already registered or the Registry cannot find any {@link
   *     com.google.crypto.tink.KeyManager} or {@link com.google.crypto.tink.Catalogue} that can
   *     handle the entry. In both cases the error message should show how to resolve it.
   */
  public static void register(RegistryConfig config) throws GeneralSecurityException {
    for (KeyTypeEntry entry : config.getEntryList()) {
      registerKeyType(entry);
    }
  }

  /**
   * Tries to register a key manager according to the specification in {@code entry}.
   *
   * @throws GeneralSecurityException if cannot register this config with the {@link Registry}. This
   *     usually happens when {@code entry} is already registered or the Registry cannot find any
   *     {@link com.google.crypto.tink.KeyManager} or {@link com.google.crypto.tink.Catalogue} that
   *     can handle the entry. In both cases the error message should show how to resolve it.
   */
  public static void registerKeyType(KeyTypeEntry entry) throws GeneralSecurityException {
    validate(entry);
    // Catalogues are no longer supported; we simply return on those catalogues which have been
    // removed, as the key managers will be registered already.
    if (entry.getCatalogueName().equals("TinkAead")
        || entry.getCatalogueName().equals("TinkMac")
        || entry.getCatalogueName().equals("TinkHybridDecrypt")
        || entry.getCatalogueName().equals("TinkHybridEncrypt")
        || entry.getCatalogueName().equals("TinkPublicKeySign")
        || entry.getCatalogueName().equals("TinkPublicKeyVerify")
        || entry.getCatalogueName().equals("TinkStreamingAead")
        || entry.getCatalogueName().equals("TinkDeterministicAead")) {
      return;
    }
    Catalogue<?> catalogue = Registry.getCatalogue(entry.getCatalogueName());
    Registry.registerPrimitiveWrapper(catalogue.getPrimitiveWrapper());
    KeyManager<?> keyManager =
        catalogue.getKeyManager(
            entry.getTypeUrl(), entry.getPrimitiveName(), entry.getKeyManagerVersion());
    Registry.registerKeyManager(keyManager, entry.getNewKeyAllowed());
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

  private Config() {}
}
