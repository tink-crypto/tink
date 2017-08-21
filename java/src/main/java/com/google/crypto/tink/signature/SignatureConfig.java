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

import com.google.crypto.tink.Config;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.RegistryConfig;
import java.security.GeneralSecurityException;

/**
 * This class offers convenience methods and constants for initializing
 * {@link PublicKeySignFactory} and the underlying {@link Registry}.
 *
 * For more information on how to obtain and use PublicKeySign primitives,
 * see {@link PublicKeySignFactory}.
 */
public final class SignatureConfig {
  private static final String CATALOGUE_NAME = "TinkSignature";

  public static final RegistryConfig TINK_1_0_0 = RegistryConfig.newBuilder()
        .setConfigName("TINK_SIGNATURE_SIGN_1_0_0")
        .addEntry(Config.getTinkKeyTypeEntry(
            CATALOGUE_NAME, "PublicKeySign", "EcdsaPrivateKey", 0, true))
        .addEntry(Config.getTinkKeyTypeEntry(
            CATALOGUE_NAME, "PublicKeySign", "Ed25519PrivateKey", 0, true))
        .addEntry(Config.getTinkKeyTypeEntry(
            CATALOGUE_NAME, "PublicKeyVerify", "EcdsaPublicKey", 0, true))
        .addEntry(Config.getTinkKeyTypeEntry(
            CATALOGUE_NAME, "PublicKeyVerify", "Ed25519PublicKey", 0, true))
        .build();

  static {
    try {
      init();
    } catch (GeneralSecurityException e) {
      throw new ExceptionInInitializerError(e);
    }
  }

  /**
   * Registers all {@link PublicKeyVerify} and {@link PublicKeySign} catalogues with the
   * {@link Registry}.
   */
  public static void init() throws GeneralSecurityException {
    Registry.addCatalogue(CATALOGUE_NAME, new SignatureCatalogue());
  }
}
