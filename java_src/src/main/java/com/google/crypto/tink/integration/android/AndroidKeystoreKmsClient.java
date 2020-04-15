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

import android.annotation.TargetApi;
import android.os.Build;
import android.os.Build.VERSION_CODES;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.subtle.Validators;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import javax.crypto.KeyGenerator;

/**
 * An implementation of {@link KmsClient} for <a
 * href="https://developer.android.com/training/articles/keystore.html">Android Keystore</a>.
 *
 * <p>This class requires Android M (API level 23) or newer.
 *
 * @since 1.0.0
 */
@TargetApi(VERSION_CODES.M)
public final class AndroidKeystoreKmsClient implements KmsClient {
  /** The prefix of all keys stored in Android Keystore. */
  public static final String PREFIX = "android-keystore://";

  private String keyUri;

  public AndroidKeystoreKmsClient() throws GeneralSecurityException {
    if (!isAtLeastM()) {
      throw new GeneralSecurityException(
          "needs Android Keystore on Android M or newer");
    }
  }

  /**
   * Constructs an {@link AndroidKeystoreKmsClient} that is bound to a single key identified by
   * {@code uri}.
   */
  public AndroidKeystoreKmsClient(String uri) {
    if (!uri.toLowerCase().startsWith(PREFIX)) {
      throw new IllegalArgumentException("key URI must starts with " + PREFIX);
    }
    this.keyUri = uri;
  }

  /**
   * @return true either if {@link AndroidKeystoreKmsClient#keyUri} is not null and equal to {@code
   *     uri}, or {@link AndroidKeystoreKmsClient#keyUri} is null and {@code uri} starts with {@link
   *     AndroidKeystoreKmsClient#PREFIX}.
   */
  @Override
  public boolean doesSupport(String uri) {
    if (this.keyUri != null && this.keyUri.equals(uri)) {
      return true;
    }
    return this.keyUri == null && uri.toLowerCase().startsWith(PREFIX);
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

  private boolean isAtLeastM() {
    return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M;
  }

  @Override
  public Aead getAead(String uri) throws GeneralSecurityException {
    if (this.keyUri != null && !this.keyUri.equals(uri)) {
      throw new GeneralSecurityException(
          String.format("this client is bound to %s, cannot load keys bound to %s",
              this.keyUri, uri));
    }
    try {
      return new AndroidKeystoreAesGcm(
          Validators.validateKmsKeyUriAndRemovePrefix(PREFIX, uri));
    } catch (IOException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * Generates a new key in Android Keystore, if it doesn't exist.
   *
   * <p>At the moment it can generate only AES256-GCM keys.
   */
  public static Aead getOrGenerateNewAeadKey(String keyUri)
      throws GeneralSecurityException, IOException {
    String keyId = Validators.validateKmsKeyUriAndRemovePrefix(PREFIX, keyUri);
    KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
    keyStore.load(null /* param */);
    if (!keyStore.containsAlias(keyId)) {
      generateNewAeadKey(keyUri);
    }
    return new AndroidKeystoreKmsClient().getAead(keyUri);
  }

  /**
   * Generates a new key in Android Keystore.
   *
   * <p>At the moment it can generate only AES256-GCM keys.
   */
  public static void generateNewAeadKey(String keyUri)
      throws GeneralSecurityException {
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
}
