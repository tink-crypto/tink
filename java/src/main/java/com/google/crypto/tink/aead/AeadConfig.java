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

import com.google.crypto.tink.Config;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.proto.RegistryConfig;
import java.security.GeneralSecurityException;

/**
 * Static methods and constants for registering with the {@link Registry} all instances of {@link
 * com.google.crypto.tink.Aead} key types supported in a particular release of Tink.
 *
 * <p>To register all Aead key types provided in the latest Tink version one can do:
 *
 * <pre>{@code
 * AeadConfig.register();
 * }</pre>
 *
 * @since 1.0.0
 */
public final class AeadConfig {
  public static final String AES_CTR_HMAC_AEAD_TYPE_URL = AesCtrHmacAeadKeyManager.TYPE_URL;
  public static final String AES_GCM_TYPE_URL = AesGcmKeyManager.TYPE_URL;
  public static final String AES_EAX_TYPE_URL = AesEaxKeyManager.TYPE_URL;
  public static final String KMS_AEAD_TYPE_URL = KmsAeadKeyManager.TYPE_URL;
  public static final String KMS_ENVELOPE_AEAD_TYPE_URL = KmsEnvelopeAeadKeyManager.TYPE_URL;
  public static final String CHACHA20_POLY1305_TYPE_URL = ChaCha20Poly1305KeyManager.TYPE_URL;
  public static final String XCHACHA20_POLY1305_TYPE_URL = XChaCha20Poly1305KeyManager.TYPE_URL;

  private static final String CATALOGUE_NAME = "TinkAead";
  private static final String PRIMITIVE_NAME = "Aead";

  /** @deprecated */
  @Deprecated
  public static final RegistryConfig TINK_1_0_0 =
      RegistryConfig.newBuilder()
          .mergeFrom(MacConfig.TINK_1_0_0)
          .addEntry(
              Config.getTinkKeyTypeEntry(
                  CATALOGUE_NAME, PRIMITIVE_NAME, "AesCtrHmacAeadKey", 0, true))
          .addEntry(
              Config.getTinkKeyTypeEntry(CATALOGUE_NAME, PRIMITIVE_NAME, "AesEaxKey", 0, true))
          .addEntry(
              Config.getTinkKeyTypeEntry(CATALOGUE_NAME, PRIMITIVE_NAME, "AesGcmKey", 0, true))
          .addEntry(
              Config.getTinkKeyTypeEntry(
                  CATALOGUE_NAME, PRIMITIVE_NAME, "ChaCha20Poly1305Key", 0, true))
          .addEntry(
              Config.getTinkKeyTypeEntry(CATALOGUE_NAME, PRIMITIVE_NAME, "KmsAeadKey", 0, true))
          .addEntry(
              Config.getTinkKeyTypeEntry(
                  CATALOGUE_NAME, PRIMITIVE_NAME, "KmsEnvelopeAeadKey", 0, true))
          .setConfigName("TINK_AEAD_1_0_0")
          .build();

  /**
   * @deprecated
   * @since 1.1.0
   */
  @Deprecated
  public static final RegistryConfig TINK_1_1_0 =
      RegistryConfig.newBuilder().mergeFrom(TINK_1_0_0).setConfigName("TINK_AEAD_1_1_0").build();

  /** @since 1.2.0 */
  public static final RegistryConfig LATEST =
      RegistryConfig.newBuilder()
          .mergeFrom(MacConfig.LATEST)
          .addEntry(
              Config.getTinkKeyTypeEntry(
                  CATALOGUE_NAME, PRIMITIVE_NAME, "AesCtrHmacAeadKey", 0, true))
          .addEntry(
              Config.getTinkKeyTypeEntry(CATALOGUE_NAME, PRIMITIVE_NAME, "AesEaxKey", 0, true))
          .addEntry(
              Config.getTinkKeyTypeEntry(CATALOGUE_NAME, PRIMITIVE_NAME, "AesGcmKey", 0, true))
          .addEntry(
              Config.getTinkKeyTypeEntry(
                  CATALOGUE_NAME, PRIMITIVE_NAME, "ChaCha20Poly1305Key", 0, true))
          .addEntry(
              Config.getTinkKeyTypeEntry(CATALOGUE_NAME, PRIMITIVE_NAME, "KmsAeadKey", 0, true))
          .addEntry(
              Config.getTinkKeyTypeEntry(
                  CATALOGUE_NAME, PRIMITIVE_NAME, "KmsEnvelopeAeadKey", 0, true))
          .addEntry(
              Config.getTinkKeyTypeEntry(
                  CATALOGUE_NAME, PRIMITIVE_NAME, "XChaCha20Poly1305Key", 0, true))
          .setConfigName("TINK_AEAD")
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
   * com.google.crypto.tink.Catalogue} and {@link com.google.crypto.tink.KeyManager} needed to
   * handle Aead key types supported in Tink.
   *
   * <p>Because Aead key types depend on {@link com.google.crypto.tink.Mac} key types, this method
   * also registers all Mac catalogues and key managers.
   *
   * @deprecated use {@link #register}
   */
  @Deprecated
  public static void init() throws GeneralSecurityException {
    register();
  }

  /**
   * Tries to register with the {@link Registry} all instances of {@link
   * com.google.crypto.tink.Catalogue} and {@link com.google.crypto.tink.KeyManager} needed to
   * handle Aead key types supported in Tink.
   *
   * <p>Because Aead key types depend on {@link com.google.crypto.tink.Mac} key types, this method
   * also registers all Mac catalogues and key managers.
   *
   * @since 1.2.0
   */
  public static void register() throws GeneralSecurityException {
    // The order of these calls matters.
    MacConfig.register();
    Registry.addCatalogue(CATALOGUE_NAME, new AeadCatalogue());
    Config.register(LATEST);
  }

  /**
   * Registers with the {@code Registry} all Aead key types released with the latest version of
   * Tink.
   *
   * <p>Deprecated-yet-still-supported key types are registered in so-called "no new key"-mode,
   * which allows for usage of existing keys forbids generation of new key material.
   *
   * @deprecated use {@link #register}
   */
  @Deprecated
  public static void registerStandardKeyTypes() throws GeneralSecurityException {
    register();
  }
}
