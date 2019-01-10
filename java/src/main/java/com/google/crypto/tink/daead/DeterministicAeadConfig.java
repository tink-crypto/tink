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

import com.google.crypto.tink.Config;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.RegistryConfig;
import java.security.GeneralSecurityException;

/**
 * Static methods and constants for registering with the {@link Registry} all instances of {@link
 * com.google.crypto.tink.DeterministicAead} key types supported in a particular release of Tink.
 *
 * <p>To register all DeterministicAead key types provided in the latest Tink version one can do:
 *
 * <pre>{@code
 * DeterministicAeadConfig.register();
 * }</pre>
 *
 * <p>For more information on how to obtain and use instances of DeterministicAead, see {@link
 * DeterministicAeadFactory}.
 *
 * @since 1.1.0
 */
public final class DeterministicAeadConfig {
  public static final String AES_SIV_TYPE_URL = AesSivKeyManager.TYPE_URL;

  private static final String CATALOGUE_NAME = "TinkDeterministicAead";
  private static final String PRIMITIVE_NAME = "DeterministicAead";

  /** @deprecated */
  @Deprecated
  public static final RegistryConfig TINK_1_1_0 =
      RegistryConfig.newBuilder()
          .addEntry(
              Config.getTinkKeyTypeEntry(CATALOGUE_NAME, PRIMITIVE_NAME, "AesSivKey", 0, true))
          .setConfigName("TINK_DETERMINISTIC_AEAD_1_1_0")
          .build();

  /** @since 1.2.0 */
  public static final RegistryConfig LATEST =
      RegistryConfig.newBuilder()
          .addEntry(
              Config.getTinkKeyTypeEntry(CATALOGUE_NAME, PRIMITIVE_NAME, "AesSivKey", 0, true))
          .setConfigName("TINK_DETERMINISTIC_AEAD")
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
   * com.google.crypto.tink.Catalogue} needed to handle DeterministicAead key types supported in
   * Tink.
   *
   * <p>Because DeterministicAead key types depend on {@link com.google.crypto.tink.Mac} key types,
   * this method also registers all Mac catalogues.
   *
   * @deprecated use {@link #register}
   */
  @Deprecated
  public static void init() throws GeneralSecurityException {
    register();
  }

  /**
   * Tries to register with the {@link Registry} all instances of {@link
   * com.google.crypto.tink.Catalogue} needed to handle DeterministicAead key types supported in
   * Tink.
   *
   * @since 1.2.0
   */
  public static void register() throws GeneralSecurityException {
    Registry.addCatalogue(CATALOGUE_NAME, new DeterministicAeadCatalogue());
    Config.register(LATEST);
    Registry.registerPrimitiveWrapper(new DeterministicAeadWrapper());
  }
}
