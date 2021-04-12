// Copyright 2020 Google LLC
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

package com.google.crypto.tink.jwt;

import java.security.GeneralSecurityException;

/**
 * Static methods and constants for registering with the {@link com.google.crypto.tink.Registry} all
 * instances of {@link JwtMac} key types supported in a particular release of Tink.
 *
 * <p>To register all {@link JwtMac} key types provided in the latest Tink version one can do:
 *
 * <pre>{@code
 * JwtMacConfig.register();
 * }</pre>
 *
 * <p>For more information on how to obtain and use instances of {@link JwtMac}, see {@link
 * com.google.crypto.tink.KeysetHandle#getPrimitive}.
 */
public final class JwtMacConfig {
  public static final String JWT_HMAC_TYPE_URL = new JwtHmacKeyManager().getKeyType();

  /**
   * Tries to register with the {@link com.google.crypto.tink.Registry} all instances of {@link
   * com.google.crypto.tink.KeyManager} needed to handle JWT key types supported in Tink.
   */
  public static void register() throws GeneralSecurityException {
    JwtHmacKeyManager.register(true);
    JwtMacWrapper.register();
  }

  private JwtMacConfig() {}
}
