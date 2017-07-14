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

import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.KeyTypeEntry;
import com.google.crypto.tink.proto.TinkConfig;
import java.security.GeneralSecurityException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.logging.Logger;

/**
 * Helper for handling of Tink configurations, i.e. of key types and
 * their corresponding key managers supported by a specific run-time
 * environment.
 *
 * Configurations enable control of Tink setup via text-formatted
 * config files that determine which key types are supported, and
 * provide a mechanism for deprecation of obsolete/outdated
 * cryptographic schemes (see {@code config.proto} for more info).
 *
 * In addition to methods for registering configurations, this class
 * contains also constants with configuration examples that can be used
 * for initializing the Registry.
 *
 * For example, to use Aead key types provided in release 1.0.0
 * one initializes the resgistry via:
 *
 * <pre><code>
 * Config.register(Config.TINK_AEAD_1_0_0);
 * </code></pre>
 *
 * To register all key types provided in Tink release 1.0.0 one would use instead:
 *
 * <pre><code>
 * Config.register(Config.TINK_1_0_0);
 * </code></pre>
 *
 * Of course, one can also use a custom configuration to initialize the Registry:
 *
 * <pre><code>
 * TinkConfig customTinkConfig = ... // e.g. load from a file
 * Config.register(customTinkConfig);
 * </code></pre>
 */
public final class Config {
  private static final Logger logger = Logger.getLogger(Config.class.getName());

  private static final TinkCatalogue tinkCatalogue = new TinkCatalogue();
  private static final ConcurrentMap<String, Catalogue> customCatalogue =
      new ConcurrentHashMap<String, Catalogue>();   //  name -> catalogue mapping

  private static KeyTypeEntry getTinkKeyTypeEntry(String primitiveName, String keyProtoName,
      int keyManagerVersion, boolean newKeyAllowed) {
    return KeyTypeEntry.newBuilder()
        .setPrimitiveName(primitiveName)
        .setTypeUrl("type.googleapis.com/google.crypto.tink." + keyProtoName)
        .setKeyManagerVersion(keyManagerVersion)
        .setNewKeyAllowed(newKeyAllowed)
        .setCatalogueName("Tink")
        .build();
  }

  // ----------------------------------------------------------------------------------------------
  // Configs specifying key types supported in Tink Release 1.0.0
  // Each config is "self-sufficient" in the sense that it includes also all the key types
  // used as sub-primitives for the key types it contains.
  // For example TINK_AEAD_1_0_0 includes TINK_MAC_1_0_0, and
  // TINK_HYBRID_ENCRYPT_1_0_0 includes TINK_AEAD_1_0_0.
  public static final TinkConfig TINK_1_0_0;           // contains all Release 1 key types.
  public static final TinkConfig TINK_MAC_1_0_0;       // MAC key types
  public static final TinkConfig TINK_AEAD_1_0_0;      // AEAD key types
  public static final TinkConfig TINK_HYBRID_1_0_0;    // hybrid encryption and decryption
  public static final TinkConfig TINK_HYBRID_ENCRYPT_1_0_0;    // hybrid encryption
  public static final TinkConfig TINK_HYBRID_DECRYPT_1_0_0;    // hybrid decryption
  public static final TinkConfig TINK_SIGNATURE_1_0_0;         // digital signatures
  public static final TinkConfig TINK_SIGNATURE_VERIFY_1_0_0;  // signatures, verification
  public static final TinkConfig TINK_SIGNATURE_SIGN_1_0_0;    // signatures, signing

  static {
    TINK_MAC_1_0_0 = TinkConfig.newBuilder()
        .setConfigName("TINK_MAC_1_0_0")
        .addEntry(getTinkKeyTypeEntry("Mac", "HmacKey", 0, true))
        .build();
    TINK_AEAD_1_0_0 = TinkConfig.newBuilder()
        .mergeFrom(TINK_MAC_1_0_0)
        .setConfigName("TINK_AEAD_1_0_0")
        .addEntry(getTinkKeyTypeEntry("Aead", "AesCtrHmacAeadKey", 0, true))
        .addEntry(getTinkKeyTypeEntry("Aead", "AesEaxKey", 0, true))
        .addEntry(getTinkKeyTypeEntry("Aead", "AesGcmKey", 0, true))
        .addEntry(getTinkKeyTypeEntry("Aead", "ChaCha20Poly1305Key", 0, true))
        .build();
    TINK_HYBRID_1_0_0 = TinkConfig.newBuilder()
        .mergeFrom(TINK_AEAD_1_0_0)
        .setConfigName("TINK_HYBRID_1_0_0")
        .addEntry(getTinkKeyTypeEntry("HybridEncrypt", "EciesAeadHkdfPublicKey", 0, true))
        .addEntry(getTinkKeyTypeEntry("HybridDecrypt", "EciesAeadHkdfPrivateKey", 0, true))
        .build();
    TINK_HYBRID_ENCRYPT_1_0_0 = TinkConfig.newBuilder()
        .mergeFrom(TINK_AEAD_1_0_0)
        .setConfigName("TINK_HYBRID_ENCRYPT_1_0_0")
        .addEntry(getTinkKeyTypeEntry("HybridEncrypt", "EciesAeadHkdfPublicKey", 0, true))
        .build();
    TINK_HYBRID_DECRYPT_1_0_0 = TinkConfig.newBuilder()
        .mergeFrom(TINK_AEAD_1_0_0)
        .setConfigName("TINK_HYBRID_DECRYPT_1_0_0")
        .addEntry(getTinkKeyTypeEntry("HybridDecrypt", "EciesAeadHkdfPrivateKey", 0, true))
        .build();
    TINK_SIGNATURE_1_0_0 = TinkConfig.newBuilder()
        .setConfigName("TINK_SIGNATURE_1_0_0")
        .addEntry(getTinkKeyTypeEntry("PublicKeySign", "EcdsaPrivateKey", 0, true))
        .addEntry(getTinkKeyTypeEntry("PublicKeySign", "Ed25519PrivateKey", 0, true))
        .addEntry(getTinkKeyTypeEntry("PublicKeyVerify", "EcdsaPublicKey", 0, true))
        .addEntry(getTinkKeyTypeEntry("PublicKeyVerify", "Ed25519PublicKey", 0, true))
        .build();
    TINK_SIGNATURE_VERIFY_1_0_0 = TinkConfig.newBuilder()
        .setConfigName("TINK_SIGNATURE_VERIFY_1_0_0")
        .addEntry(getTinkKeyTypeEntry("PublicKeyVerify", "EcdsaPublicKey", 0, true))
        .addEntry(getTinkKeyTypeEntry("PublicKeyVerify", "Ed25519PublicKey", 0, true))
        .build();
    TINK_SIGNATURE_SIGN_1_0_0 = TinkConfig.newBuilder()
        .setConfigName("TINK_SIGNATURE_SIGN_1_0_0")
        .addEntry(getTinkKeyTypeEntry("PublicKeySign", "EcdsaPrivateKey", 0, true))
        .addEntry(getTinkKeyTypeEntry("PublicKeySign", "Ed25519PrivateKey", 0, true))
        .build();
    TINK_1_0_0 = TinkConfig.newBuilder()
        .mergeFrom(TINK_AEAD_1_0_0)
        .setConfigName("TINK_1_0_0")
        .addEntry(getTinkKeyTypeEntry("HybridEncrypt", "EciesAeadHkdfPublicKey", 0, true))
        .addEntry(getTinkKeyTypeEntry("HybridDecrypt", "EciesAeadHkdfPrivateKey", 0, true))
        .addEntry(getTinkKeyTypeEntry("PublicKeyVerify", "EcdsaPublicKey", 0, true))
        .addEntry(getTinkKeyTypeEntry("PublicKeyVerify", "Ed25519PublicKey", 0, true))
        .addEntry(getTinkKeyTypeEntry("PublicKeySign", "EcdsaPrivateKey", 0, true))
        .addEntry(getTinkKeyTypeEntry("PublicKeySign", "Ed25519PrivateKey", 0, true))
        .build();
  }

  /**
   * Adds a custom catalogue, to enable custom configuration of key types
   * and key managers used by Tink.
   */
  public static void addCustomCatalogue(String catalogueName, Catalogue catalogue)
      throws GeneralSecurityException {
    if (catalogueName == null) {
      throw new NullPointerException("catalogueName must be non-null.");
    }
    if (catalogue == null) {
      throw new NullPointerException("catalogue must be non-null.");
    }
    customCatalogue.put(catalogueName.toLowerCase(), catalogue);
  }

  /**
   * Registers key managers according to the specification in {@code config}.
   */
  public static void register(TinkConfig config) throws GeneralSecurityException {
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
    Catalogue catalogue = getCatalogue(entry.getCatalogueName());
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

  private static Catalogue getCatalogue(String catalogueName) throws GeneralSecurityException {
    if (catalogueName.toLowerCase().equals("tink")) {
      return tinkCatalogue;
    } else {
      Catalogue catalogue = customCatalogue.get(catalogueName.toLowerCase());
      if (catalogue == null) {
        throw new GeneralSecurityException("No custom catalogue: " + catalogueName);
      }
      return catalogue;
    }
  }

}
