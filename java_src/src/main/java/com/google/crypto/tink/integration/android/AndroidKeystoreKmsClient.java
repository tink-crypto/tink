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
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.Arrays;
import java.util.Locale;
import javax.annotation.concurrent.GuardedBy;
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
  private static final String TAG = AndroidKeystoreKmsClient.class.getSimpleName();
  private static final int WAIT_TIME_MILLISECONDS_BEFORE_RETRY = 20;

  /** The prefix of all keys stored in Android Keystore. */
  public static final String PREFIX = "android-keystore://";

  private final String keyUri;

  @GuardedBy("this")
  private KeyStore keyStore;

  public AndroidKeystoreKmsClient() throws GeneralSecurityException {
    this(new Builder());
  }

  /**
   * Constructs an {@link AndroidKeystoreKmsClient} that is bound to a single key identified by
   * {@code uri}.
   *
   * @deprecated use {@link AndroidKeystoreKmsClient.Builder}.
   */
  @Deprecated
  public AndroidKeystoreKmsClient(String uri) {
    this(new Builder().setKeyUri(uri));
  }

  private AndroidKeystoreKmsClient(Builder builder) {
    this.keyUri = builder.keyUri;
    this.keyStore = builder.keyStore;
  }

  /** Builder for AndroidKeystoreKmsClient */
  public static final class Builder {
    String keyUri = null;
    KeyStore keyStore = null;

    public Builder() {
      if (!isAtLeastM()) {
        throw new IllegalStateException("need Android Keystore on Android M or newer");
      }

      try {
        this.keyStore = KeyStore.getInstance("AndroidKeyStore");
        this.keyStore.load(/* param= */ null);
      } catch (GeneralSecurityException | IOException ex) {
        throw new IllegalStateException(ex);
      }
    }

    public Builder setKeyUri(String val) {
      if (val == null || !val.toLowerCase(Locale.US).startsWith(PREFIX)) {
        throw new IllegalArgumentException("val must start with " + PREFIX);
      }
      this.keyUri = val;
      return this;
    }

    /** This is for testing only */
    public Builder setKeyStore(KeyStore val) {
      if (val == null) {
        throw new IllegalArgumentException("val cannot be null");
      }
      this.keyStore = val;
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
  public synchronized boolean doesSupport(String uri) {
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
  public KmsClient withCredentials(String unused) throws GeneralSecurityException {
    return new AndroidKeystoreKmsClient();
  }

  /**
   * Initializes a {@code KmsClient} for Android Keystore.
   *
   * <p>Note that Android Keystore does not use credentials.
   */
  @Override
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
  public synchronized Aead getAead(String uri) throws GeneralSecurityException {
    if (this.keyUri != null && !this.keyUri.equals(uri)) {
      throw new GeneralSecurityException(
          String.format("this client is bound to %s, cannot load keys bound to %s",
              this.keyUri, uri));
    }
    Aead aead =
        new AndroidKeystoreAesGcm(
            Validators.validateKmsKeyUriAndRemovePrefix(PREFIX, uri), keyStore);
    return validateAead(aead);
  }

  /** Deletes a key in Android Keystore. */
  public synchronized void deleteKey(String keyUri) throws GeneralSecurityException {
    String keyId = Validators.validateKmsKeyUriAndRemovePrefix(PREFIX, keyUri);
    this.keyStore.deleteEntry(keyId);
  }

  /** Returns whether a key exists in Android Keystore. */
  synchronized boolean hasKey(String keyUri) throws GeneralSecurityException {
    String keyId = Validators.validateKmsKeyUriAndRemovePrefix(PREFIX, keyUri);
    try {
      return this.keyStore.containsAlias(keyId);
    } catch (NullPointerException ex1) {
      // TODO(b/167402931): figure out how to test this.
      Log.w(
          TAG,
          "Keystore is temporarily unavailable, wait 20ms, reinitialize Keystore and try again.");
      try {
        Thread.sleep(WAIT_TIME_MILLISECONDS_BEFORE_RETRY);
        this.keyStore = KeyStore.getInstance("AndroidKeyStore");
        this.keyStore.load(/* param= */ null);
      } catch (IOException ex2) {
        throw new GeneralSecurityException(ex2);
      } catch (InterruptedException ex) {
        // Ignored.
      }
      return this.keyStore.containsAlias(keyId);
    }
  }

  /**
   * Generates a new key in Android Keystore, if it doesn't exist.
   *
   * <p>At the moment it can generate only AES256-GCM keys.
   */
  public static Aead getOrGenerateNewAeadKey(String keyUri)
      throws GeneralSecurityException, IOException {
    AndroidKeystoreKmsClient client = new AndroidKeystoreKmsClient();
    if (!client.hasKey(keyUri)) {
      Log.i(TAG, String.format("key URI %s doesn't exist, generating a new one", keyUri));
      generateNewAeadKey(keyUri);
    }
    return client.getAead(keyUri);
  }

  /**
   * Generates a new key in Android Keystore.
   *
   * <p>At the moment it can generate only AES256-GCM keys.
   */
  public static void generateNewAeadKey(String keyUri)
      throws GeneralSecurityException {
    AndroidKeystoreKmsClient client = new AndroidKeystoreKmsClient();
    if (client.hasKey(keyUri)) {
      throw new IllegalArgumentException(
          String.format(
              "cannot generate a new key %s because it already exists; please delete it with"
                  + " deleteKey() and try again",
              keyUri));
    }

    String keyId = Validators.validateKmsKeyUriAndRemovePrefix(PREFIX, keyUri);
    KeyGenerator keyGenerator = KeyGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
    KeyGenParameterSpec spec =
        new KeyGenParameterSpec.Builder(keyId,
            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build();
    keyGenerator.init(spec);
    keyGenerator.generateKey();
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

  private static boolean isAtLeastM() {
    return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M;
  }
}
