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

import com.google.crypto.tink.daead.DeterministicAeadConfig;
import com.google.crypto.tink.hybrid.HybridConfig;
import com.google.crypto.tink.prf.PrfConfig;
import com.google.crypto.tink.proto.RegistryConfig;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.streamingaead.StreamingAeadConfig;
import java.security.GeneralSecurityException;

/**
 * Static methods and constants for registering with the {@link com.google.crypto.tink.Registry} all
 * instances of all key types supported in a particular release of Tink.
 *
 * <p>To register all key types provided in the latest Tink version one can do:
 *
 * <pre>{@code
 * TinkConfig.register();
 * }</pre>
 *
 * @since 1.0.0
 */
public final class TinkConfig {
  /**
   * @deprecated Configs are not supported anymore. Please call {@code TinkConfig.register();}
   * instead of accessing this variable.
   */
  @Deprecated public static final RegistryConfig TINK_1_0_0 = RegistryConfig.getDefaultInstance();

  /**
   * @deprecated Configs are not supported anymore. Please call {@code TinkConfig.register();}
   * instead of accessing this variable.
   */
  @Deprecated public static final RegistryConfig TINK_1_1_0 = RegistryConfig.getDefaultInstance();

  /**
   * @deprecated Configs are not supported anymore. Please call {@code TinkConfig.register();}
   * instead of accessing this variable.
   */
  @Deprecated
  public static final RegistryConfig LATEST = RegistryConfig.getDefaultInstance();

  /**
   * Tries to register with the {@link Registry} all instances of {@link
   * com.google.crypto.tink.Catalogue} and {@link com.google.crypto.tink.KeyManager} needed to
   * handle all key types supported in Tink.
   *
   * @deprecated use {@link #register}
   */
  @Deprecated
  public static void init() throws GeneralSecurityException {
    register();
  }

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
   * handle all key types supported in Tink.
   *
   * @since 1.2.0
   */
  public static void register() throws GeneralSecurityException {
    DeterministicAeadConfig.register();
    HybridConfig.register(); // includes Aead and Mac
    PrfConfig.register();
    SignatureConfig.register();
    StreamingAeadConfig.register();
  }

  private TinkConfig() {}
}
