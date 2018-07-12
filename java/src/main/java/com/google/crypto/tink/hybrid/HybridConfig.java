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

import com.google.crypto.tink.Config;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.proto.RegistryConfig;
import java.security.GeneralSecurityException;

/**
 * Static methods and constants for registering with the {@link Registry} all instances of {@link
 * com.google.crypto.tink.HybridEncrypt} and {@link com.google.crypto.tink.HybridDecrypt} key types
 * supported in a particular release of Tink.
 *
 * <p>To register all HybridEncrypt and HybridDecrypt key types provided in the latest Tink version
 * one can do:
 *
 * <pre>{@code
 * HybridConfig.register();
 * }</pre>
 *
 * <p>For more information on how to obtain and use instances of HybridEncrypt or HybridDecrypt, see
 * {@link HybridEncryptFactory} or {@link HybridDecryptFactory}.
 *
 * @since 1.0.0
 */
public final class HybridConfig {
  public static final String ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE_URL =
      EciesAeadHkdfPublicKeyManager.TYPE_URL;
  public static final String ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE_URL =
      EciesAeadHkdfPrivateKeyManager.TYPE_URL;
  private static final String HYBRID_ENCRYPT_CATALOGUE_NAME = "TinkHybridEncrypt";
  private static final String HYBRID_DECRYPT_CATALOGUE_NAME = "TinkHybridDecrypt";

  /** @deprecated */
  @Deprecated
  public static final RegistryConfig TINK_1_0_0 =
      RegistryConfig.newBuilder()
          .mergeFrom(AeadConfig.TINK_1_0_0)
          .addEntry(
              Config.getTinkKeyTypeEntry(
                  HYBRID_DECRYPT_CATALOGUE_NAME,
                  "HybridDecrypt",
                  "EciesAeadHkdfPrivateKey",
                  0,
                  true))
          .addEntry(
              Config.getTinkKeyTypeEntry(
                  HYBRID_ENCRYPT_CATALOGUE_NAME,
                  "HybridEncrypt",
                  "EciesAeadHkdfPublicKey",
                  0,
                  true))
          .setConfigName("TINK_HYBRID_1_0_0")
          .build();

  /**
   * @deprecated
   * @since 1.1.0
   */
  @Deprecated
  public static final RegistryConfig TINK_1_1_0 =
      RegistryConfig.newBuilder().mergeFrom(TINK_1_0_0).setConfigName("TINK_HYBRID_1_1_0").build();

  /** @since 1.2.0 */
  public static final RegistryConfig LATEST =
      RegistryConfig.newBuilder()
          .mergeFrom(AeadConfig.LATEST)
          .addEntry(
              Config.getTinkKeyTypeEntry(
                  HYBRID_DECRYPT_CATALOGUE_NAME,
                  "HybridDecrypt",
                  "EciesAeadHkdfPrivateKey",
                  0,
                  true))
          .addEntry(
              Config.getTinkKeyTypeEntry(
                  HYBRID_ENCRYPT_CATALOGUE_NAME,
                  "HybridEncrypt",
                  "EciesAeadHkdfPublicKey",
                  0,
                  true))
          .setConfigName("TINK_HYBRID")
          .build();

  static {
    try {
      init();
    } catch (GeneralSecurityException e) {
      throw new ExceptionInInitializerError(e);
    }
  }

  /**
   * Tries to register with the {@link Registry} all instances of {@link
   * com.google.crypto.tink.Catalogue} needed to handle HybridDecrypt and HybridEncrypt key types
   * supported in Tink.
   *
   * <p>Because HybridDecrypt and HybridEncrypt key types depend on {@link
   * com.google.crypto.tink.Aead} and {@link com.google.crypto.tink.Mac} key types, this method also
   * registers all Aead and Mac catalogues.
   *
   * @deprecated use {@link #register}
   */
  @Deprecated
  public static void init() throws GeneralSecurityException {
    register();
  }

  /**
   * Tries to register with the {@link Registry} all instances of {@link
   * com.google.crypto.tink.Catalogue} needed to handle HybridDecrypt and HybridEncrypt key types
   * supported in Tink.
   *
   * <p>Because HybridDecrypt and HybridEncrypt key types depend on {@link
   * com.google.crypto.tink.Aead} and {@link com.google.crypto.tink.Mac} key types, this method also
   * registers all Aead and Mac catalogues.
   *
   * @since 1.2.0
   */
  public static void register() throws GeneralSecurityException {
    // The order of these calls matters.
    AeadConfig.register(); // includes Mac
    Registry.addCatalogue(HYBRID_ENCRYPT_CATALOGUE_NAME, new HybridEncryptCatalogue());
    Registry.addCatalogue(HYBRID_DECRYPT_CATALOGUE_NAME, new HybridDecryptCatalogue());
    Config.register(LATEST);
  }
}
