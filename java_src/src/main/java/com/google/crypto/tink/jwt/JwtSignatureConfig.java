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

package com.google.crypto.tink.jwt;

import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.proto.RegistryConfig;
import java.security.GeneralSecurityException;

/**
 * Static methods and constants for registering with the {@link com.google.crypto.tink.Registry} all
 * instances of {@link com.google.crypto.tink.jwt.JwtPublicKeySign} and {@link
 * com.google.crypto.tink.jwt.JwtPublicKeyVerify} key types supported in a particular release of
 * Tink.
 *
 * <p>To register all JwtPublicKeySign and JwtPublicKeyVerify key types provided in the latest Tink
 * version one can do:
 *
 * <pre>{@code
 * JwtSignatureConfig.register();
 * }</pre>
 */
public final class JwtSignatureConfig {
  public static final String JWT_ECDSA_PUBLIC_KEY_TYPE_URL =
      new JwtEcdsaVerifyKeyManager().getKeyType();
  public static final String JWT_ECDSA_PRIVATE_KEY_TYPE_URL =
      new JwtEcdsaSignKeyManager().getKeyType();

  public static final String JWT_RSA_PKCS1_PRIVATE_KEY_TYPE_URL =
      new JwtRsaSsaPkcs1SignKeyManager().getKeyType();
  public static final String JWT_RSA_PKCS1_PUBLIC_KEY_TYPE_URL =
      new JwtRsaSsaPkcs1VerifyKeyManager().getKeyType();

  public static final String JWT_RSA_PSS_PRIVATE_KEY_TYPE_URL =
      new JwtRsaSsaPssSignKeyManager().getKeyType();
  public static final String JWT_RSA_PSS_PUBLIC_KEY_TYPE_URL =
      new JwtRsaSsaPssVerifyKeyManager().getKeyType();

  public static final RegistryConfig LATEST = RegistryConfig.getDefaultInstance();

  /**
   * Tries to register with the {@link com.google.crypto.tink.Registry} all instances of {@link
   * com.google.crypto.tink.Catalogue} needed to handle JwtPublicKeySign and PublicKeyVerify key
   * types supported in Tink.
   */
  public static void register() throws GeneralSecurityException {
    JwtPublicKeySignWrapper.register();
    JwtPublicKeyVerifyWrapper.register();

    JwtEcdsaSignKeyManager.registerPair(/*newKeyAllowed=*/ true);
    JwtRsaSsaPkcs1SignKeyManager.registerPair(/* newKeyAllowed= */ true);

    if (TinkFips.useOnlyFips()) {
      // If Tink is built in FIPS-mode do not register algorithms which are not compatible.
      return;
    }

    JwtRsaSsaPssSignKeyManager.registerPair(/* newKeyAllowed= */ true);
  }

  private JwtSignatureConfig() {}
}
