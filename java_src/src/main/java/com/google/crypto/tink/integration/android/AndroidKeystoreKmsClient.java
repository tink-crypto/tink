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

package com.google.crypto.tink.integration.android;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import androidx.annotation.ChecksSdkIntAtLeast;
import androidx.annotation.RequiresApi;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.Arrays;
import java.util.Locale;
import javax.crypto.KeyGenerator;

/**
 * An implementation of {@link KmsClient} for <a
 * href="https://developer.android.com/training/articles/keystore.html">Android Keystore</a>.
 *
 * <p>This class requires Android M (API level 23) or newer.
 *
 * @since 1.0.0
 */
public final class AndroidKeystoreKmsClient implements KmsClient {
  private static final Object keystoreLock = new Object();

  private static final String TAG = AndroidKeystoreKmsClient.class.getSimpleName();
  private static final int MAX_WAIT_TIME_MILLISECONDS_BEFORE_RETRY = 40;

  /** The prefix of all keys stored in Android Keystore. */
  public static final String PREFIX = "android-keystore://";

  private final String keyUri;

  @RequiresApi(23)
  public AndroidKeystoreKmsClient() throws GeneralSecurityException {
    this(new Builder());
  }

  /**
   * Constructs an {@link AndroidKeystoreKmsClient} that is bound to a single key identified by
   * {@code uri}.
   *
   * @deprecated use {@link AndroidKeystoreKmsClient.Builder}.
   */
  @RequiresApi(23)
  @Deprecated
  public AndroidKeystoreKmsClient(String uri) {
    this(new Builder().setKeyUri(uri));
  }

  private AndroidKeystoreKmsClient(Builder builder) {
    this.keyUri = builder.keyUri;
  }

  /** Builder for AndroidKeystoreKmsClient */
  public static final class Builder {
    String keyUri = null;

    @RequiresApi(23)
    public Builder() {
      if (!isAtLeastM()) {
        throw new IllegalStateException("need Android Keystore on Android M or newer");
      }
    }

    @CanIgnoreReturnValue
    @RequiresApi(23)
    public Builder setKeyUri(String val) {
      if (val == null || !val.toLowerCase(Locale.US).startsWith(PREFIX)) {
        throw new IllegalArgumentException("val must start with " + PREFIX);
      }
      this.keyUri = val;
      return this;
    }

    public AndroidKeystoreKmsClient build() {
      return new AndroidKeystoreKmsClient(this);
    }
  }

  /**
   * @return true either if {@link AndroidKeystoreKmsClient#keyUri} is not null and equal to {@code
   *     uri}, or {@link AndroidKeystoreKmsClient#keyUri} is null and {@code uri} starts with {@link
   *     AndroidKeystoreKmsClient#PREFIX}.
   */
  @Override
  @RequiresApi(23)
  public boolean doesSupport(String uri) {
    if (this.keyUri != null && this.keyUri.equals(uri)) {
      return true;
    }
    return this.keyUri == null && uri.toLowerCase(Locale.US).startsWith(PREFIX);
  }

  /**
   * Initializes a {@link KmsClient} for Android Keystore.
   *
   * <p>Note that Android Keystore doesn't need credentials, thus the credential path is unused.
   */
  @Override
  @RequiresApi(23)
  public KmsClient withCredentials(String unused) throws GeneralSecurityException {
    return new AndroidKeystoreKmsClient();
  }

  /**
   * Initializes a {@code KmsClient} for Android Keystore.
   *
   * <p>Note that Android Keystore does not use credentials.
   */
  @Override
  @RequiresApi(23)
  public KmsClient withDefaultCredentials() throws GeneralSecurityException {
    return new AndroidKeystoreKmsClient();
  }

  /**
   * Returns an {@link Aead} backed by a key in Android Keystore specified by {@code uri}.
   *
   * <p>Since Android Keystore is somewhat unreliable, a self-test is done against the key. This
   * will incur a small performance penalty.
   */
  @Override
  public Aead getAead(String uri) throws GeneralSecurityException {
    if (this.keyUri != null && !this.keyUri.equals(uri)) {
      throw new GeneralSecurityException(
          String.format(
              "this client is bound to %s, cannot load keys bound to %s", this.keyUri, uri));
    }
    try {
      synchronized (keystoreLock) {
        Aead aead =
            new AndroidKeystoreAesGcm(Validators.validateKmsKeyUriAndRemovePrefix(PREFIX, uri));
        return validateAead(aead);
      }
    } catch (IOException ex) {
      throw new GeneralSecurityException(ex);
    }
  }

  private static KeyStore getAndroidKeyStore() throws GeneralSecurityException {
    try {
      KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
      keyStore.load(/* param= */ null);
      return keyStore;
    } catch (IOException ex) {
      throw new GeneralSecurityException(ex);
    }
  }

  /** Deletes a key in Android Keystore. */
  public void deleteKey(String keyUri) throws GeneralSecurityException {
    String keyId = Validators.validateKmsKeyUriAndRemovePrefix(PREFIX, keyUri);
    synchronized (keystoreLock) {
      getAndroidKeyStore().deleteEntry(keyId);
    }
  }

  /** Returns whether a key exists in Android Keystore. */
  boolean hasKey(String keyUri) throws GeneralSecurityException {
    String keyId = Validators.validateKmsKeyUriAndRemovePrefix(PREFIX, keyUri);
    try {
      synchronized (keystoreLock) {
        return getAndroidKeyStore().containsAlias(keyId);
      }
    } catch (NullPointerException ex1) {
      Log.w(TAG, "Keystore is temporarily unavailable, wait, reinitialize Keystore and try again.");
      sleepRandomAmount();
      synchronized (keystoreLock) {
        return getAndroidKeyStore().containsAlias(keyId);
      }
    }
  }

  private static void sleepRandomAmount() {
    int waitTimeMillis = (int) (Math.random() * MAX_WAIT_TIME_MILLISECONDS_BEFORE_RETRY);
    try {
      Thread.sleep(waitTimeMillis);
    } catch (InterruptedException ex) {
      // Ignored.
    }
  }

  /**
   * Generates a new key in Android Keystore, if it doesn't exist.
   *
   * <p>Generates AES256-GCM keys.
   */
  @RequiresApi(Build.VERSION_CODES.M)
  public static Aead getOrGenerateNewAeadKey(String keyUri)
      throws GeneralSecurityException, IOException {
    AndroidKeystoreKmsClient client = new AndroidKeystoreKmsClient();
    synchronized (keystoreLock) {
      if (!client.hasKey(keyUri)) {
        generateNewAesGcmKeyWithoutExistenceCheck(keyUri);
      }
      return client.getAead(keyUri);
    }
  }

  /**
   * Generates a new key in Android Keystore.
   *
   * <p>Generates AES256-GCM keys.
   */
  @RequiresApi(Build.VERSION_CODES.M)
  public static void generateNewAeadKey(String keyUri) throws GeneralSecurityException {
    AndroidKeystoreKmsClient client = new AndroidKeystoreKmsClient();
    synchronized (keystoreLock) {
      if (client.hasKey(keyUri)) {
        throw new IllegalArgumentException(
            String.format(
                "cannot generate a new key %s because it already exists; please delete it with"
                    + " deleteKey() and try again",
                keyUri));
      }
      generateNewAesGcmKeyWithoutExistenceCheck(keyUri);
    }
  }

  /**
   * Generates a new AES256-GCM key in Android Keystore.
   *
   * <p>This function does not check if the key already exists, and will overwrite any existing key.
   */
  @RequiresApi(Build.VERSION_CODES.M)
  private static void generateNewAesGcmKeyWithoutExistenceCheck(String keyUri)
      throws GeneralSecurityException {
    String keyId = Validators.validateKmsKeyUriAndRemovePrefix(PREFIX, keyUri);
    KeyGenerator keyGenerator =
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
    KeyGenParameterSpec spec =
        new KeyGenParameterSpec.Builder(
                keyId, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .build();
    keyGenerator.init(spec);
    keyGenerator.generateKey();
  }

  /**
   * Checks if the key exists, and generates a new one if it does not yet exist.
   *
   * <p>Returns true if a new key was generated.
   */
  @RequiresApi(Build.VERSION_CODES.M)
  static boolean generateKeyIfNotExist(String keyUri) throws GeneralSecurityException {
    AndroidKeystoreKmsClient client = new AndroidKeystoreKmsClient();
    synchronized (keystoreLock) {
      if (!client.hasKey(keyUri)) {
        generateNewAesGcmKeyWithoutExistenceCheck(keyUri);
        return true;
      }
      return false;
    }
  }

  /** Does a self-test to verify whether we can rely on Android Keystore */
  private static Aead validateAead(Aead aead) throws GeneralSecurityException {
    // Non-empty message and empty aad.
    // This is a combination that usually fails.
    byte[] message = Random.randBytes(10);
    byte[] aad = new byte[0];
    byte[] ciphertext = aead.encrypt(message, aad);
    byte[] decrypted = aead.decrypt(ciphertext, aad);
    if (!Arrays.equals(message, decrypted)) {
      throw new KeyStoreException(
          "cannot use Android Keystore: encryption/decryption of non-empty message and empty"
              + " aad returns an incorrect result");
    }
    return aead;
  }

  @ChecksSdkIntAtLeast(api = Build.VERSION_CODES.M)
  private static boolean isAtLeastM() {
    return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M;
  }
}
