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

package com.google.crypto.tink.mac;

import com.google.crypto.tink.Config;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.RegistryConfig;
import java.security.GeneralSecurityException;

/**
 * Static methods and constants for registering with the {@link Registry} all instances of {@link
 * com.google.crypto.tink.Mac} key types supported in a particular release of Tink.
 *
 * <p>To register all Mac key types provided in Tink release 1.0.0 one can do:
 *
 * <pre>{@code
 * Config.register(MacConfig.TINK_1_0_0);
 * }</pre>
 *
 * <p>For more information on how to obtain and use instances of Mac, see {@link MacFactory}.
 */
public final class MacConfig {
  public static final String HMAC_TYPE_URL = HmacKeyManager.TYPE_URL;

  private static final String CATALOGUE_NAME = "TinkMac";
  private static final String PRIMITIVE_NAME = "Mac";

  public static final RegistryConfig TINK_1_0_0 =
      RegistryConfig.newBuilder()
          .setConfigName("TINK_MAC_1_0_0")
          .addEntry(Config.getTinkKeyTypeEntry(CATALOGUE_NAME, PRIMITIVE_NAME, "HmacKey", 0, true))
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
   * com.google.crypto.tink.Catalogue} needed to handle Mac key types supported in Tink.
   */
  public static void init() throws GeneralSecurityException {
    Registry.addCatalogue(CATALOGUE_NAME, new MacCatalogue());
  }

  /**
   * Registers with the {@code Registry} all Mac key types released with the latest version of Tink.
   *
   * <p>Deprecated-yet-still-supported key types are registered in so-called "no new key"-mode,
   * which allows for usage of existing keys forbids generation of new key material.
   *
   * @deprecated
   */
  @Deprecated
  public static void registerStandardKeyTypes() throws GeneralSecurityException {
    Config.register(TINK_1_0_0);
  }
}
