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

import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.proto.RegistryConfig;
import com.google.errorprone.annotations.InlineMe;
import java.security.GeneralSecurityException;

/**
 * Static methods and constants for registering with the {@link com.google.crypto.tink.Registry} all
 * instances of {@link com.google.crypto.tink.DeterministicAead} key types supported in a particular
 * release of Tink.
 *
 * <p>To register all DeterministicAead key types provided in the latest Tink version one can do:
 *
 * <pre>{@code
 * DeterministicAeadConfig.register();
 * }</pre>
 *
 * <p>For more information on how to obtain and use instances of DeterministicAead, see {@link
 * com.google.crypto.tink.KeysetHandle#getPrimitive}.
 *
 * @since 1.1.0
 */
public final class DeterministicAeadConfig {
  public static final String AES_SIV_TYPE_URL = new AesSivKeyManager().getKeyType();

  /** @deprecated use {@link #register} */
  @Deprecated public static final RegistryConfig TINK_1_1_0 = RegistryConfig.getDefaultInstance();

  /**
   * @deprecated use {@link #register}
   * @since 1.2.0
   */
  @Deprecated public static final RegistryConfig LATEST = RegistryConfig.getDefaultInstance();

  static {
    try {
      register();
    } catch (GeneralSecurityException e) {
      throw new ExceptionInInitializerError(e);
    }
  }

  /**
   * Tries to register with the {@link com.google.crypto.tink.Registry} all instances of {@link
   * com.google.crypto.tink.Catalogue} needed to handle DeterministicAead key types supported in
   * Tink.
   *
   * <p>Because DeterministicAead key types depend on {@link com.google.crypto.tink.Mac} key types,
   * this method also registers all Mac catalogues.
   *
   * @deprecated use {@link #register}
   */
  @InlineMe(
      replacement = "DeterministicAeadConfig.register()",
      imports = "com.google.crypto.tink.daead.DeterministicAeadConfig")
  @Deprecated
  public static void init() throws GeneralSecurityException {
    register();
  }

  /**
   * Tries to register with the {@link com.google.crypto.tink.Registry} all instances of {@link
   * com.google.crypto.tink.Catalogue} needed to handle DeterministicAead key types supported in
   * Tink.
   *
   * @since 1.2.0
   */
  public static void register() throws GeneralSecurityException {
    DeterministicAeadWrapper.register();

    if (TinkFips.useOnlyFips()) {
      // If Tink is built in FIPS-mode do not register algorithms which are not compatible.
      // Currently there are no determinstic AEADs which are compatible and therefore none will
      // be registered.
      return;
    }
    AesSivKeyManager.register(/* newKeyAllowed = */ true);
  }

  private DeterministicAeadConfig() {}
}
