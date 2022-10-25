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
public final class EngineFactory<T_WRAPPER extends EngineWrapper<JcePrimitiveT>, JcePrimitiveT> {
  private static final Logger logger = Logger.getLogger(EngineFactory.class.getName());
  private final Policy<JcePrimitiveT> policy;

  /**
   * A Policy provides a wrapper around the JCE engines, and defines how a cipher instance will be
   * retrieved. A preferred list of providers can be passed, which the policy might use to
   * prioritize certain providers. For details see the specific policies.
   */
  private static interface Policy<JcePrimitiveT> {
    public JcePrimitiveT getInstance(String algorithm) throws GeneralSecurityException;

    public JcePrimitiveT getInstance(String algorithm, List<Provider> preferredProviders)
        throws GeneralSecurityException;
  }

  /**
   * The default policy, which uses the JDK priority for providers. If a list of preferred providers
   * is provided, then these will be used first in the order they are given.
   */
  private static class DefaultPolicy<JcePrimitiveT> implements Policy<JcePrimitiveT> {
    private DefaultPolicy(EngineWrapper<JcePrimitiveT> jceFactory) {
      this.jceFactory = jceFactory;
    }

    @Override
    public JcePrimitiveT getInstance(String algorithm) throws GeneralSecurityException {
      return this.jceFactory.getInstance(algorithm, null);
    }

    @Override
    public JcePrimitiveT getInstance(String algorithm, List<Provider> preferredProviders)
        throws GeneralSecurityException {
      for (Provider provider : preferredProviders) {
        try {
          return this.jceFactory.getInstance(algorithm, provider);
        } catch (Exception e) {
          // Provider failed to provide instance, but we can continue with other providers.
        }
      }
      return getInstance(algorithm);
    }

    private final EngineWrapper<JcePrimitiveT> jceFactory;
  }

  /**
   * The FIPS policy, only allows Conscrypt as a provider. No other provider will be used, and any
   * preferred provider will be ignored.
   */
  private static class FipsPolicy<JcePrimitiveT> implements Policy<JcePrimitiveT> {
    private FipsPolicy(EngineWrapper<JcePrimitiveT> jceFactory) {
      this.jceFactory = jceFactory;
    }

    @Override
    public JcePrimitiveT getInstance(String algorithm) throws GeneralSecurityException {
      List<Provider> conscryptProviders =
          toProviderList("GmsCore_OpenSSL", "AndroidOpenSSL", "Conscrypt");
      Exception cause = null;
      for (Provider provider : conscryptProviders) {
        try {
          return this.jceFactory.getInstance(algorithm, provider);
        } catch (Exception e) {
          if (cause == null) {
            cause = e;
          }
        }
      }
      throw new GeneralSecurityException("No good Provider found.", cause);
    }

    @Override
    public JcePrimitiveT getInstance(String algorithm, List<Provider> preferredProviders)
        throws GeneralSecurityException {
      // Ignores preferred provider, as we don't allow overruling the policy.
      return getInstance(algorithm);
    }

    private final EngineWrapper<JcePrimitiveT> jceFactory;
  }

  /**
   * The Android policy always prefer Conscrypt as a provider, but allows to fallback on the JDK
   * behavior if these are not available. Preferred providers will be ignored.
   */
  private static class AndroidPolicy<JcePrimitiveT> implements Policy<JcePrimitiveT> {
    private AndroidPolicy(EngineWrapper<JcePrimitiveT> jceFactory) {
      this.jceFactory = jceFactory;
    }

    @Override
    public JcePrimitiveT getInstance(String algorithm) throws GeneralSecurityException {
      List<Provider> conscryptProviders = toProviderList("GmsCore_OpenSSL", "AndroidOpenSSL");
      Exception cause = null;
      for (Provider provider : conscryptProviders) {
        try {
          return this.jceFactory.getInstance(algorithm, provider);
        } catch (Exception e) {
          if (cause == null) {
            cause = e;
          }
        }
      }
      return this.jceFactory.getInstance(algorithm, null);
    }

    @Override
    public JcePrimitiveT getInstance(String algorithm, List<Provider> preferredProviders)
        throws GeneralSecurityException {
      // Ignores preferred provider, as we don't allow overruling the policy.
      return getInstance(algorithm);
    }

    private final EngineWrapper<JcePrimitiveT> jceFactory;
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
    if (TinkFipsUtil.useOnlyFips()) {
      policy = new FipsPolicy<>(instanceBuilder);
    } else if (SubtleUtil.isAndroid()) {
      policy = new AndroidPolicy<>(instanceBuilder);
    } else {
      policy = new DefaultPolicy<>(instanceBuilder);
    }
  }

  public JcePrimitiveT getInstance(String algorithm) throws GeneralSecurityException {
    return policy.getInstance(algorithm);
  }

  JcePrimitiveT getInstance(String algorithm, List<Provider> preferredProviders)
      throws GeneralSecurityException {
    return policy.getInstance(algorithm, preferredProviders);
  }
}
