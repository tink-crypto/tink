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

package com.google.crypto.tink.subtle;

import com.google.crypto.tink.config.internal.TinkFipsUtil;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

/**
 * A factory that returns JCE engines, using pre-specified j.security.Providers.
 *
 * <p>This class contains a lot of static factories and static functions returning factories: these
 * allow customization and hide the typing complexity in this class. To use this class, import it,
 * and replace your <code>Cipher.getInstance(...)</code> with <code>
 * EngineFactory.CIPHER.getInstance(...)</code>.
 *
 * @since 1.0.0
 */
public final class EngineFactory<T_WRAPPER extends EngineWrapper<T_ENGINE>, T_ENGINE> {
  private static final Logger logger = Logger.getLogger(EngineFactory.class.getName());
  private static final List<Provider> policy;
  private static final boolean LET_FALLBACK;

  // Warning: keep this above the initialization of static providers below. or you'll get null
  // pointer errors (due to this policy not being initialized).
  static {
    if (TinkFipsUtil.useOnlyFips()) {
      // The only accepted provider is Conscrypt in FIPS-mode and no fallback is allowed.
      policy = toProviderList("GmsCore_OpenSSL", "AndroidOpenSSL", "Conscrypt");
      LET_FALLBACK = false;
    } else if (SubtleUtil.isAndroid()) {
      // TODO(thaidn): test this when Android building and testing are supported.
      // On Android prefer Conscrypt, but allow fallback to other providers.
      policy =
          toProviderList(
              "GmsCore_OpenSSL" /* Conscrypt in GmsCore, updatable thus preferrable */,
              "AndroidOpenSSL" /* Conscrypt in AOSP, not updatable but still better than BC */);
      LET_FALLBACK = true;
    } else {
      policy = new ArrayList<>();
      LET_FALLBACK = true;
    }
  }

  public static final EngineFactory<EngineWrapper.TCipher, Cipher> CIPHER =
      new EngineFactory<>(new EngineWrapper.TCipher());

  public static final EngineFactory<EngineWrapper.TMac, Mac> MAC =
      new EngineFactory<>(new EngineWrapper.TMac());

  public static final EngineFactory<EngineWrapper.TSignature, Signature> SIGNATURE =
      new EngineFactory<>(new EngineWrapper.TSignature());

  public static final EngineFactory<EngineWrapper.TMessageDigest, MessageDigest> MESSAGE_DIGEST =
      new EngineFactory<>(new EngineWrapper.TMessageDigest());

  public static final EngineFactory<EngineWrapper.TKeyAgreement, KeyAgreement> KEY_AGREEMENT =
      new EngineFactory<>(new EngineWrapper.TKeyAgreement());

  public static final EngineFactory<EngineWrapper.TKeyPairGenerator, KeyPairGenerator>
      KEY_PAIR_GENERATOR = new EngineFactory<>(new EngineWrapper.TKeyPairGenerator());

  public static final EngineFactory<EngineWrapper.TKeyFactory, KeyFactory> KEY_FACTORY =
      new EngineFactory<>(new EngineWrapper.TKeyFactory());

  /** Helper function to get a list of Providers from names. */
  public static List<Provider> toProviderList(String... providerNames) {
    List<Provider> providers = new ArrayList<>();
    for (String s : providerNames) {
      Provider p = Security.getProvider(s);
      if (p != null) {
        providers.add(p);
      } else {
        logger.info(String.format("Provider %s not available", s));
      }
    }
    return providers;
  }

  public EngineFactory(T_WRAPPER instanceBuilder) {
    this.instanceBuilder = instanceBuilder;
  }

  public T_ENGINE getInstance(String algorithm) throws GeneralSecurityException {
    Exception cause = null;
    for (Provider provider : policy) {
      try {
        return this.instanceBuilder.getInstance(algorithm, provider);
      } catch (Exception e) {
        if (cause == null) {
          cause = e;
        }
      }
    }
    if (LET_FALLBACK) {
      return this.instanceBuilder.getInstance(algorithm, null);
    }
    throw new GeneralSecurityException("No good Provider found.", cause);
  }

  private final T_WRAPPER instanceBuilder;
}
