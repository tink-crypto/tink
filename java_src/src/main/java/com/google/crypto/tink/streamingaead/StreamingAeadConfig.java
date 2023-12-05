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

package com.google.crypto.tink.streamingaead;

import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.proto.RegistryConfig;
import java.security.GeneralSecurityException;

/**
 * Static methods and constants for registering with the {@link com.google.crypto.tink.Registry} all
 * instances of {@link com.google.crypto.tink.StreamingAead} key types supported in a particular
 * release of Tink.
 *
 * <p>To register all StreamingAead key types provided in the latest Tink version one can do:
 *
 * <pre>{@code
 * StreamingAeadConfig.init();
 * }</pre>
 *
 * <p>For more information on how to obtain and use instances of StreamingAead, see {@link
 * StreamingAeadFactory}.
 *
 * @since 1.1.0
 */
public final class StreamingAeadConfig {
  public static final String AES_CTR_HMAC_STREAMINGAEAD_TYPE_URL =
      initializeClassReturnInput("type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey");
  public static final String AES_GCM_HKDF_STREAMINGAEAD_TYPE_URL =
      initializeClassReturnInput("type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey");

  /**
   * @deprecated
   */
  @Deprecated
  public static final RegistryConfig TINK_1_1_0 = RegistryConfig.getDefaultInstance();

  /** @since 1.2.0 */
  public static final RegistryConfig LATEST = RegistryConfig.getDefaultInstance();

  static {
    try {
      init();
    } catch (GeneralSecurityException e) {
      throw new ExceptionInInitializerError(e);
    }
  }

  /**
   * Returns the input, but crucially also calls the static initializer just above.
   *
   * <p>Before some refactorings, the string constants in this class were defined as: <code>
   * private final static string AES_CTR_HMAC_AEAD_TYPE_URL = new SomeKeyMananger().get();
   * </code>. After the refactorings, it would be tempting to define them as <code>
   * AES_CTR_HMAC_AEAD_TYPE_URL = "...";</code> However, this would change the behavior. By the JLS
   * §12.4.1, the static initializer of the class is called if "A static field declared by T is used
   * and the field is not a constant variable". The §4.12.4 explains that a constant variable is a
   * "final variable of type String which is initialized with a constant expression". Hence, after
   * the above refactoring the initializer wouldn't be called anymore.
   *
   * <p>Because of this, we always call this function here to enforce calling the static
   * initializer, i.e. to enforce that when a user accesses any of the variables here, the class is
   * initialized.
   */
  private static String initializeClassReturnInput(String s) {
    return s;
  }

  /**
   * Tries to register with the {@link com.google.crypto.tink.Registry} all instances of {@link
   * com.google.crypto.tink.Catalogue} needed to handle StreamingAead key types supported in Tink.
   *
   * @deprecated use {@link #register}
   */
  @Deprecated
  public static void init() throws GeneralSecurityException {
    register();
  }

  /**
   * Tries to register with the {@link com.google.crypto.tink.Registry} all instances of {@link
   * com.google.crypto.tink.Catalogue} needed to handle StreamingAead key types supported in Tink.
   *
   * @since 1.2.0
   */
  public static void register() throws GeneralSecurityException {
    StreamingAeadWrapper.register();

    if (TinkFips.useOnlyFips()) {
      // If Tink is built in FIPS-mode do not register algorithms which are not compatible.
      // Currently there are no FIPS compliant Streaming AEADs available, therefore no
      // key manager will be registered.
      return;
    }

    AesCtrHmacStreamingKeyManager.register(/* newKeyAllowed = */ true);
    AesGcmHkdfStreamingKeyManager.register(/* newKeyAllowed = */ true);
  }

  private StreamingAeadConfig() {}
}
