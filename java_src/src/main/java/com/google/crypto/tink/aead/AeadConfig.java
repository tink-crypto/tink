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

import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.proto.RegistryConfig;
import java.security.GeneralSecurityException;

/**
 * Static methods and constants for registering with the {@link com.google.crypto.tink.Registry} all
 * instances of {@link com.google.crypto.tink.Aead} key types supported in a particular release of
 * Tink.
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
  public static final String AES_CTR_HMAC_AEAD_TYPE_URL =
      initializeClassReturnInput("type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey");
  public static final String AES_GCM_TYPE_URL =
      initializeClassReturnInput("type.googleapis.com/google.crypto.tink.AesGcmKey");
  public static final String AES_GCM_SIV_TYPE_URL =
      initializeClassReturnInput("type.googleapis.com/google.crypto.tink.AesGcmSivKey");
  public static final String AES_EAX_TYPE_URL =
      initializeClassReturnInput("type.googleapis.com/google.crypto.tink.AesEaxKey");
  public static final String KMS_AEAD_TYPE_URL =
      initializeClassReturnInput("type.googleapis.com/google.crypto.tink.KmsAeadKey");
  public static final String KMS_ENVELOPE_AEAD_TYPE_URL =
      initializeClassReturnInput("type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey");
  public static final String CHACHA20_POLY1305_TYPE_URL =
      initializeClassReturnInput("type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key");
  public static final String XCHACHA20_POLY1305_TYPE_URL =
      initializeClassReturnInput("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key");

  /**
   * @deprecated use {@link #register}
   */
  @Deprecated
  public static final RegistryConfig TINK_1_0_0 = RegistryConfig.getDefaultInstance();

  /**
   * @deprecated use {@link #register}
   * @since 1.1.0
   */
  @Deprecated
  public static final RegistryConfig TINK_1_1_0 = TINK_1_0_0;

  /**
   * @deprecated use {@link #register}
   * @since 1.2.0
   */
  @Deprecated
  public static final RegistryConfig LATEST = TINK_1_0_0;

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
   * Tries to register with the {@link com.google.crypto.tink.Registry} all instances of {@link
   * com.google.crypto.tink.Catalogue} and {@link com.google.crypto.tink.KeyManager} needed to
   * handle Aead key types supported in Tink.
   *
   * <p>Because Aead key types depend on {@link com.google.crypto.tink.Mac} key types, this method
   * also registers all Mac catalogues and key managers.
   *
   * @since 1.2.0
   */
  public static void register() throws GeneralSecurityException {
    AeadWrapper.register();

    MacConfig.register();
    AesCtrHmacAeadKeyManager.register(/*newKeyAllowed=*/ true);
    AesGcmKeyManager.register(/*newKeyAllowed=*/ true);

    if (TinkFips.useOnlyFips()) {
      // If Tink is built in FIPS-mode do not register algorithms which are not compatible.
      return;
    }

    AesEaxKeyManager.register(/*newKeyAllowed=*/ true);
    AesGcmSivKeyManager.register(/*newKeyAllowed=*/ true);
    ChaCha20Poly1305KeyManager.register(/*newKeyAllowed=*/ true);
    KmsAeadKeyManager.register(/*newKeyAllowed=*/ true);
    KmsEnvelopeAeadKeyManager.register(/*newKeyAllowed=*/ true);
    XChaCha20Poly1305KeyManager.register(/*newKeyAllowed=*/ true);
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

  private AeadConfig() {}
}
