// Copyright 2022 Google LLC
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

package com.google.crypto.tink.integration.android.internal;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import com.google.crypto.tink.subtle.Random;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Fake implementations of AndroidKeystore that provide all the function needed by Tink's android
 * integration package.
 *
 * <pre>Example usage: {@code
 * java.security.Security.removeProvider("AndroidKeyStore");
 * java.security.Security.addProvider(FakeAndroidKeystoreProvider.newProvider());
 * }</pre>
 */
public final class FakeAndroidKeystoreProvider {

  /** A partial fake implementation of KeyStoreSpi. */
  public static class FakeKeyStoreSpi extends KeyStoreSpi {

    public FakeKeyStoreSpi() {}

    protected static HashMap<String, SecretKey> keys;

    public static void setKeysMapRef(HashMap<String, SecretKey> keys) {
      FakeKeyStoreSpi.keys = keys;
    }

    @Override
    public boolean engineContainsAlias(String alias) {
      return keys.containsKey(alias);
    }

    @Override
    public Key engineGetKey(String keyId, char[] password)
        throws NoSuchAlgorithmException, UnrecoverableKeyException {
      return keys.get(keyId);
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
      keys.remove(alias);
    }

    @Override
    public void engineLoad(KeyStore.LoadStoreParameter parameter)
        throws CertificateException, NoSuchAlgorithmException, IOException {}

    @Override
    public void engineLoad(InputStream inputStream, char[] password)
        throws IOException, NoSuchAlgorithmException, CertificateException {}

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
      throw new UnsupportedOperationException();
    }

    @Override
    public Certificate engineGetCertificate(String s) {
      throw new UnsupportedOperationException();
    }

    @Override
    public Date engineGetCreationDate(String s) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
        throws KeyStoreException {
      throw new UnsupportedOperationException();
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] keyBytes, Certificate[] chain)
        throws KeyStoreException {
      throw new UnsupportedOperationException();
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate certificate)
        throws KeyStoreException {
      throw new UnsupportedOperationException();
    }

    @Override
    public Enumeration<String> engineAliases() {
      throw new UnsupportedOperationException();
    }

    @Override
    public int engineSize() {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
      throw new UnsupportedOperationException();
    }

    @Override
    public String engineGetCertificateAlias(Certificate certificate) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void engineStore(KeyStore.LoadStoreParameter parameter)
        throws CertificateException, NoSuchAlgorithmException, IOException {
      throw new UnsupportedOperationException();
    }

    @Override
    public void engineStore(OutputStream outputStream, char[] password)
        throws IOException, NoSuchAlgorithmException, CertificateException {
      throw new UnsupportedOperationException();
    }
  }

  /** A partial fake implementation of KeyGeneratorSpi. */
  public static class FakeKeyGeneratorSpi extends KeyGeneratorSpi {
    public FakeKeyGeneratorSpi() {}

    private KeyGenParameterSpec spec;

    protected static HashMap<String, SecretKey> keys;

    public static void setKeysMapRef(HashMap<String, SecretKey> keys) {
      FakeKeyGeneratorSpi.keys = keys;
    }

    @Override
    public SecretKey engineGenerateKey() {
      SecretKey newKey = new SecretKeySpec(Random.randBytes(32), "AES");
      keys.put(spec.getKeystoreAlias(), newKey);
      return newKey;
    }

    @Override
    public void engineInit(AlgorithmParameterSpec params, SecureRandom random) {
      if (!(params instanceof KeyGenParameterSpec)) {
        throw new UnsupportedOperationException("unsupported params");
      }
      KeyGenParameterSpec keyGenParams = (KeyGenParameterSpec) params;
      if (keyGenParams.getPurposes()
          != (KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)) {
        throw new UnsupportedOperationException("unsupported purposes");
      }
      if (keyGenParams.getKeySize() != 256) {
        throw new UnsupportedOperationException("unsupported key size");
      }
      if (keyGenParams.getBlockModes().length != 1) {
        throw new UnsupportedOperationException("unsupported block modes length");
      }
      if (!keyGenParams.getBlockModes()[0].equals(KeyProperties.BLOCK_MODE_GCM)) {
        throw new UnsupportedOperationException("unsupported block mode");
      }
      if (keyGenParams.getEncryptionPaddings().length != 1) {
        throw new UnsupportedOperationException("unsupported encryption paddings length");
      }
      if (!keyGenParams.getEncryptionPaddings()[0].equals(KeyProperties.ENCRYPTION_PADDING_NONE)) {
        throw new UnsupportedOperationException("unsupported encryption padding");
      }
      spec = keyGenParams;
    }

    @Override
    public void engineInit(int keysize, SecureRandom random) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void engineInit(SecureRandom random) {
      throw new UnsupportedOperationException();
    }
  }

  @SuppressWarnings(
      "deprecation") // We need to use the old constructor to support older Java versions.
  private static class FakeProvider extends Provider {
    FakeProvider() {
      super("AndroidKeyStore", 1.0, "Fake AndroidKeyStore");

      // The keys map is shared by FakeKeyStoreSpi and FakeKeyGeneratorSpi.
      HashMap<String, SecretKey> keys = new HashMap<>();
      FakeKeyStoreSpi.setKeysMapRef(keys);
      FakeKeyGeneratorSpi.setKeysMapRef(keys);

      put("KeyStore.AndroidKeyStore", FakeKeyStoreSpi.class.getName());
      put("KeyGenerator.AES", FakeKeyGeneratorSpi.class.getName());
    }
  }

  /** Returns a new fake Provider for AndroidKeystore. */
  public static Provider newProvider() {
    return new FakeProvider();
  }

  /**
   * A fake KeyStoreSpi implementation that may raise a NullPointerException in engineContainsAlias.
   *
   * <p>This is added because of b/167402931.
   */
  public static class UnreliableFakeKeyStoreSpi
      extends FakeAndroidKeystoreProvider.FakeKeyStoreSpi {

    public UnreliableFakeKeyStoreSpi() {}

    public static int failuresInARow;
    public static int failuresLeft;

    public static void setFailuresInARow(int failuresInARow) {
      UnreliableFakeKeyStoreSpi.failuresInARow = failuresInARow;
      failuresLeft = failuresInARow;
    }

    @Override
    public boolean engineContainsAlias(String alias) {
      if (failuresLeft > 0) {
        failuresLeft = failuresLeft - 1;
        throw new NullPointerException("something went wrong");
      }
      failuresLeft = failuresInARow;
      return keys.containsKey(alias);
    }
  }

  @SuppressWarnings(
      "deprecation") // We need to use the old constructor to support older Java versions.
  private static class UnreliableFakeProvider extends Provider {
    UnreliableFakeProvider(int failuresInARow) {
      super("AndroidKeyStore", 1.0, "Fake AndroidKeyStore with a bad containsAlias implementation");

      HashMap<String, SecretKey> keys = new HashMap<>();
      FakeAndroidKeystoreProvider.FakeKeyStoreSpi.setKeysMapRef(keys);
      FakeAndroidKeystoreProvider.FakeKeyGeneratorSpi.setKeysMapRef(keys);
      UnreliableFakeKeyStoreSpi.setFailuresInARow(failuresInARow);

      this.setProperty("KeyStore.AndroidKeyStore", UnreliableFakeKeyStoreSpi.class.getName());
      this.setProperty(
          "KeyGenerator.AES", FakeAndroidKeystoreProvider.FakeKeyGeneratorSpi.class.getName());
    }
  }

  /** Returns a new fake Provider for AndroidKeystore. */
  public static Provider newUnreliableProvider(int failuresInARow) {
    return new UnreliableFakeProvider(failuresInARow);
  }

  /**
   * A partial fake implementation of KeyStoreSpi where engineGetKey always throws an exception.
   *
   * <p>This is added because of b/151893419.
   */
  public static class FakeKeyStoreSpiWithUnrecoverableKeys extends FakeKeyStoreSpi {

    public FakeKeyStoreSpiWithUnrecoverableKeys() {}

    @Override
    public Key engineGetKey(String keyId, char[] password)
        throws NoSuchAlgorithmException, UnrecoverableKeyException {
      Key key = super.engineGetKey(keyId, password);
      if (key == null) {
        return null;
      }
      throw new UnrecoverableKeyException("Failed to obtain information about key");
    }
  }

  @SuppressWarnings(
      "deprecation") // We need to use the old constructor to support older Java versions.
  private static class FakeProviderWithUnrecoverableKeys extends Provider {
    FakeProviderWithUnrecoverableKeys() {
      super("AndroidKeyStore", 1.0, "Fake AndroidKeyStore that returns null keys");

      HashMap<String, SecretKey> keys = new HashMap<>();
      FakeAndroidKeystoreProvider.FakeKeyStoreSpi.setKeysMapRef(keys);
      FakeAndroidKeystoreProvider.FakeKeyGeneratorSpi.setKeysMapRef(keys);

      put("KeyStore.AndroidKeyStore", FakeKeyStoreSpiWithUnrecoverableKeys.class.getName());
      put("KeyGenerator.AES", FakeKeyGeneratorSpi.class.getName());
    }
  }

  /** Returns a new fake Provider for AndroidKeystore. */
  public static Provider newProviderWithUnrecoverableKeys() {
    return new FakeProviderWithUnrecoverableKeys();
  }

  /**
   * A fake implementation of KeyStoreSpi where engineGetKey always throws a ProviderException.
   *
   * <p>If the key is stored in StrongBox, it is possible that a ProviderException is thrown if
   * there's any problem with it.
   */
  public static class FakeKeyStoreSpiWithProviderException extends FakeKeyStoreSpi {

    public FakeKeyStoreSpiWithProviderException() {}

    @Override
    public Key engineGetKey(String keyId, char[] password)
        throws NoSuchAlgorithmException, UnrecoverableKeyException {
      throw new ProviderException("Something is wrong with the provider");
    }
  }

  @SuppressWarnings(
      "deprecation") // We need to use the old constructor to support older Java versions.
  private static class FakeProviderWithProviderException extends Provider {
    FakeProviderWithProviderException() {
      super("AndroidKeyStore", 1.0, "Fake AndroidKeyStore that throws ProviderException");

      HashMap<String, SecretKey> keys = new HashMap<>();
      FakeAndroidKeystoreProvider.FakeKeyStoreSpi.setKeysMapRef(keys);
      FakeAndroidKeystoreProvider.FakeKeyGeneratorSpi.setKeysMapRef(keys);

      put("KeyStore.AndroidKeyStore", FakeKeyStoreSpiWithProviderException.class.getName());
      put("KeyGenerator.AES", FakeKeyGeneratorSpi.class.getName());
    }
  }

  /** Returns a new fake provider where getKey always throws ProviderException. */
  public static Provider newProviderWithProviderException() {
    return new FakeProviderWithProviderException();
  }

  /** A fake implementation of KeyStoreSpi where engineGetKey always returns null. */
  public static class FakeKeyStoreSpiWithNullKeys extends FakeKeyStoreSpi {

    public FakeKeyStoreSpiWithNullKeys() {}

    @Override
    public Key engineGetKey(String keyId, char[] password)
        throws NoSuchAlgorithmException, UnrecoverableKeyException {
      return null;
    }
  }

  @SuppressWarnings(
      "deprecation") // We need to use the old constructor to support older Java versions.
  private static class FakeProviderWithNullKeys extends Provider {
    FakeProviderWithNullKeys() {
      super("AndroidKeyStore", 1.0, "Fake AndroidKeyStore that returns null keys");

      HashMap<String, SecretKey> keys = new HashMap<>();
      FakeAndroidKeystoreProvider.FakeKeyStoreSpi.setKeysMapRef(keys);
      FakeAndroidKeystoreProvider.FakeKeyGeneratorSpi.setKeysMapRef(keys);

      put("KeyStore.AndroidKeyStore", FakeKeyStoreSpiWithNullKeys.class.getName());
      put("KeyGenerator.AES", FakeKeyGeneratorSpi.class.getName());
    }
  }

  /** Returns a new fake Provider for AndroidKeystore where getKey always returns null. */
  public static Provider newProviderWithNullKeys() {
    return new FakeProviderWithNullKeys();
  }

  /** An implementation of KeyGeneratorSpi that doesn't generate keys. */
  public static class NoKeyGeneratorSpi extends FakeKeyGeneratorSpi {

    public NoKeyGeneratorSpi() {}

    @Override
    public SecretKey engineGenerateKey() {
      return null;
    }
  }

  @SuppressWarnings(
      "deprecation") // We need to use the old constructor to support older Java versions.
  private static class FakeProviderWithoutKeyGeneration extends Provider {
    FakeProviderWithoutKeyGeneration() {
      super("AndroidKeyStore", 1.0, "Fake AndroidKeyStore that returns null keys");

      HashMap<String, SecretKey> keys = new HashMap<>();
      FakeAndroidKeystoreProvider.FakeKeyStoreSpi.setKeysMapRef(keys);
      FakeAndroidKeystoreProvider.FakeKeyGeneratorSpi.setKeysMapRef(keys);

      put("KeyStore.AndroidKeyStore", FakeKeyStoreSpiWithNullKeys.class.getName());
      put("KeyGenerator.AES", NoKeyGeneratorSpi.class.getName());
    }
  }

  /** Returns a new fake Provider for AndroidKeystore that doesn't generate keys. */
  public static Provider newProviderWithoutKeyGeneration() {
    return new FakeProviderWithoutKeyGeneration();
  }

  @SuppressWarnings(
      "deprecation") // We need to use the old constructor to support older Java versions.
  private static class BadProvider extends Provider {
    BadProvider() {
      super("AndroidKeyStore", 1.0, "Fake AndroidKeyStore that throws ProviderException");

      HashMap<String, SecretKey> keys = new HashMap<>();
      FakeAndroidKeystoreProvider.FakeKeyStoreSpi.setKeysMapRef(keys);
      FakeAndroidKeystoreProvider.FakeKeyGeneratorSpi.setKeysMapRef(keys);

      put("KeyStore.AndroidKeyStore", FakeKeyStoreSpiWithProviderException.class.getName());
      put("KeyGenerator.AES", NoKeyGeneratorSpi.class.getName());
    }
  }

  /**
   * Returns a new fake Provider that doesn't generate keys and where getKey always throws
   * ProviderException.
   */
  public static Provider newBadProvider() {
    return new BadProvider();
  }

  private FakeAndroidKeystoreProvider() {}
}
