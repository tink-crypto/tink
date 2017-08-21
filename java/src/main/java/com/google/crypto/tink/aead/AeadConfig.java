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
 * This class offers convenience methods and constants for initializing
 * {@link AeadFactory} and the underlying {@link Registry}.
 *
 * <p>To register all {@link Aead} key types provided in Tink release 1.0.0 one would use:
 *
 * <pre><code>
 * Config.register(AeadConfig.TINK_1_0_0);
 * </code></pre>
 *
 * <p>For more information on how to obtain and use {@link Aead} primitives,
 * see {@link AeadFactory}.
 */
public final class AeadConfig {
  private static final String CATALOGUE_NAME = "TinkAead";
  private static final String PRIMITIVE_NAME = "Aead";

  public static final RegistryConfig TINK_1_0_0 = RegistryConfig.newBuilder()
      .mergeFrom(MacConfig.TINK_1_0_0)
      .addEntry(Config.getTinkKeyTypeEntry(
          CATALOGUE_NAME, PRIMITIVE_NAME, "AesCtrHmacAeadKey", 0, true))
      .addEntry(Config.getTinkKeyTypeEntry(
          CATALOGUE_NAME, PRIMITIVE_NAME, "AesEaxKey", 0, true))
      .addEntry(Config.getTinkKeyTypeEntry(
          CATALOGUE_NAME, PRIMITIVE_NAME, "AesGcmKey", 0, true))
      .addEntry(Config.getTinkKeyTypeEntry(
          CATALOGUE_NAME, PRIMITIVE_NAME, "ChaCha20Poly1305Key", 0, true))
      .addEntry(Config.getTinkKeyTypeEntry(
          CATALOGUE_NAME, PRIMITIVE_NAME, "KmsAeadKey", 0, true))
      .addEntry(Config.getTinkKeyTypeEntry(
          CATALOGUE_NAME, PRIMITIVE_NAME, "KmsEnvelopeAeadKey", 0, true))
      .setConfigName("TINK_AEAD_1_0_0")
      .build();

  static {
    try {
      init();
    } catch (GeneralSecurityException e) {
      throw new ExceptionInInitializerError(e);
    }
  }

  /**
   * Registers {@link Aead} catalogues with the {@link Registry}.
   *
   * <p>Because Aead key types depend on {@link Mac} key types, this method also
   * registers all {@link Mac} catalogues.
   */
  public static void init() throws GeneralSecurityException {
    Registry.addCatalogue(CATALOGUE_NAME, new AeadCatalogue());
    MacConfig.init();
  }

  /**
   * Registers standard (for the current release) Aead key types
   * and their managers with the {@code Registry}.
   *
   * Deprecated-yet-still-supported key types are registered in
   * so-called "no new key"-mode, which allows for usage of existing
   * keys forbids generation of new key material.
   *
   * @throws GeneralSecurityException
   * @deprecated
   */
  @Deprecated
  public static void registerStandardKeyTypes() throws GeneralSecurityException {
    Config.register(TINK_1_0_0);
  }
}
