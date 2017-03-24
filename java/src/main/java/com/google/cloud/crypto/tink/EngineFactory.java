
package com.google.cloud.crypto.tink;

import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.Provider;
import java.util.List;
import java.util.ArrayList;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;

/**
 * A factory that returns JCE engines, using pre-specified j.security.Providers.
 *
 * This class contains a lot of static factories and static functions returning factories: these
 * allow customization and hide the typing complexity in this class. To use this class, import it,
 * and replace your `Cipher.getInstance(...` with `EngineFactory.CIPHER.getInstance(...`.
 */
public class EngineFactory<T_WRAPPER extends EngineWrapper<T_ENGINE>, T_ENGINE> {

  // Warning: keep this above the initialization of static providers below. or you'll get null
  // pointer errors (due to this policy not being initialized).
  static private final List<Provider> defaultPolicy = new ArrayList<Provider>();
  static private final boolean defaultLetFallback = true;

  public static final EngineFactory<EngineWrapper.TCipher, Cipher> CIPHER =
      new EngineFactory<>(new EngineWrapper.TCipher());
  public static final EngineFactory<EngineWrapper.TCipher, Cipher>
      getCustomCipherProvider(boolean letFallbackToDefault, String... providerNames) {
    return new EngineFactory<EngineWrapper.TCipher, Cipher>(
        new EngineWrapper.TCipher(),
        toProviderList(providerNames),
        letFallbackToDefault);
  }

  public static final EngineFactory<EngineWrapper.TMac, Mac> MAC =
      new EngineFactory<>(new EngineWrapper.TMac());
  public static final EngineFactory<EngineWrapper.TMac, Mac>
      getCustomMacProvider(boolean letFallbackToDefault, String... providerNames) {
    return new EngineFactory<EngineWrapper.TMac, Mac>(
        new EngineWrapper.TMac(),
        toProviderList(providerNames),
        letFallbackToDefault);
  }

  public static final EngineFactory<EngineWrapper.TSignature, Signature> SIGNATURE =
      new EngineFactory<>(new EngineWrapper.TSignature());
  public static final EngineFactory<EngineWrapper.TSignature, Signature>
      getCustomSignatureProvider(boolean letFallbackToDefault, String... providerNames) {
    return new EngineFactory<EngineWrapper.TSignature, Signature>(
        new EngineWrapper.TSignature(),
        toProviderList(providerNames),
        letFallbackToDefault);
  }

  public static final EngineFactory<EngineWrapper.TMessageDigest, MessageDigest> MESSAGE_DIGEST =
      new EngineFactory<>(new EngineWrapper.TMessageDigest());
  public static final EngineFactory<EngineWrapper.TMessageDigest, MessageDigest>
      getCustomMessageDigestProvider(boolean letFallbackToDefault, String... providerNames) {
    return new EngineFactory<EngineWrapper.TMessageDigest, MessageDigest>(
        new EngineWrapper.TMessageDigest(),
        toProviderList(providerNames),
        letFallbackToDefault);
  }

  public static final EngineFactory<EngineWrapper.TKeyPairGenerator, KeyPairGenerator>
      KEY_PAIR_GENERATOR = new EngineFactory<>(new EngineWrapper.TKeyPairGenerator());
  public static final EngineFactory<EngineWrapper.TKeyPairGenerator, KeyPairGenerator>
      getCustomKeyPairGeneratorProvider(boolean letFallbackToDefault, String... providerNames) {
    return new EngineFactory<EngineWrapper.TKeyPairGenerator, KeyPairGenerator>(
        new EngineWrapper.TKeyPairGenerator(),
        toProviderList(providerNames),
        letFallbackToDefault);
  }

  /**
   * Helper function to get a list of Providers from names.
   */
  public static List<Provider> toProviderList(String... providerNames) {
    List<Provider> providers = new ArrayList<Provider>();
    for(String s : providerNames) {
      Provider p = Security.getProvider(s);
      if (p != null) {
        providers.add(p);
      }
    }
    return providers;
  }

  public EngineFactory(T_WRAPPER instanceBuilder) {
    this.instanceBuilder = instanceBuilder;
    this.policy = defaultPolicy;
    this.letFallback = defaultLetFallback;
  }

  public EngineFactory(T_WRAPPER instanceBuilder, List<Provider> policy) {
    this.instanceBuilder = instanceBuilder;
    this.policy = policy;
    this.letFallback = defaultLetFallback;
  }

  public EngineFactory(
      T_WRAPPER instanceBuilder, List<Provider> policy, boolean letFallback) {
    this.instanceBuilder = instanceBuilder;
    this.policy = policy;
    this.letFallback = letFallback;
  }

  public T_ENGINE getInstance(String algorithm) throws GeneralSecurityException {
    for (Provider p: this.policy) {
      if (tryProvider(algorithm, p)) {
        return this.instanceBuilder.getInstance(algorithm, p);
      }
    }
    if (letFallback) {
      return this.instanceBuilder.getInstance(algorithm, null);
    }
    throw new GeneralSecurityException("No good Provider found.");
  }

  private T_WRAPPER instanceBuilder;
  private List<Provider> policy;
  private boolean letFallback;

  private boolean tryProvider(String algorithm, Provider provider) {
    try {
      this.instanceBuilder.getInstance(algorithm, provider);;
      return true;
    } catch (Exception e) { // Don't care which one specifically.
      return false;
    }
  }
}
