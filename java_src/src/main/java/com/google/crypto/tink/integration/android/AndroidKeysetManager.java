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

import android.content.Context;
import android.os.Build;
import android.util.Log;
import androidx.annotation.ChecksSdkIntAtLeast;
import androidx.annotation.RequiresApi;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetManager;
import com.google.crypto.tink.KeysetReader;
import com.google.crypto.tink.KeysetWriter;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.ProviderException;
import javax.annotation.concurrent.GuardedBy;

/**
 * A wrapper of {@link KeysetManager} that supports reading/writing {@link
 * com.google.crypto.tink.proto.Keyset} to/from private shared preferences on Android.
 *
 * <h3>Warning</h3>
 *
 * <p>This class reads and writes to shared preferences, thus is best not to run on the UI thread.
 *
 * <h3>Usage</h3>
 *
 * <pre>{@code
 * // One-time operations, should be done when the application is starting up.
 * // Instead of repeatedly instantiating these crypto objects, instantiate them once and save for
 * // later use.
 * AndroidKeysetManager manager = AndroidKeysetManager.Builder()
 *    .withSharedPref(getApplicationContext(), "my_keyset_name", "my_pref_file_name")
 *    .withKeyTemplate(AesGcmHkfStreamingKeyManager.aes128GcmHkdf4KBTemplate())
 *    .build();
 * StreamingAead streamingAead = manager.getKeysetHandle().getPrimitive(StreamingAead.class);
 * }</pre>
 *
 * <p>This will read a keyset stored in the {@code my_keyset_name} preference of the {@code
 * my_pref_file_name} preferences file. If the preference file name is null, it uses the default
 * preferences file.
 *
 * <ul>
 *   <li>If a keyset is found, but it is invalid, an {@link IOException} is thrown. The most common
 *       cause is when you decrypted a keyset with a wrong master key. In this case, an {@link
 *       InvalidProtocolBufferException} would be thrown. This is an irrecoverable error. You'd have
 *       to delete the keyset in Shared Preferences and all existing data encrypted with it.
 *   <li>If a keyset is not found, and a {@link KeyTemplate} is set with {@link
 *       AndroidKeysetManager.Builder#withKeyTemplate(com.google.crypto.tink.KeyTemplate)}, a fresh
 *       keyset is generated and is written to the {@code my_keyset_name} preference of the {@code
 *       my_pref_file_name} shared preferences file.
 * </ul>
 *
 * <h3>Key rotation</h3>
 *
 * <p>The resulting manager supports all operations supported by {@link KeysetManager}. For example
 * to rotate the keyset, you can do:
 *
 * <pre>{@code
 * manager.rotate(AesGcmHkfStreamingKeyManager.aes128GcmHkdf1MBTemplate());
 * }</pre>
 *
 * <p>All operations that manipulate the keyset would automatically persist the new keyset to
 * permanent storage.
 *
 * <h3>Opportunistic keyset encryption with Android Keystore</h3>
 *
 * <b>Warning:</b> because Android Keystore is unreliable, we strongly recommend disabling it by not
 * setting any master key URI.
 *
 * <p>If a master key URI is set with {@link AndroidKeysetManager.Builder#withMasterKeyUri}, the
 * keyset may be encrypted with a key generated and stored in <a
 * href="https://developer.android.com/training/articles/keystore.html">Android Keystore</a>.
 *
 * <p>Android Keystore is only available on Android M or newer. Since it has been found that Android
 * Keystore is unreliable on certain devices. Tink runs a self-test to detect such problems and
 * disables Android Keystore accordingly, even if a master key URI is set. You can check whether
 * Android Keystore is in use with {@link #isUsingKeystore}.
 *
 * <p>When Android Keystore is disabled or otherwise unavailable, keysets will be stored in
 * cleartext. This is not as bad as it sounds because keysets remain inaccessible to any other apps
 * running on the same device. Moreover, as of July 2020, most active Android devices support either
 * full-disk encryption or file-based encryption, which provide strong security protection against
 * key theft even from attackers with physical access to the device. Android Keystore is only useful
 * when you want to <a
 * href="https://developer.android.com/training/articles/keystore#UserAuthentication">require user
 * authentication for key use</a>, which should be done if and only if you're absolutely sure that
 * Android Keystore is working properly on your target devices.
 *
 * <p>The master key URI must start with {@code android-keystore://}. The remaining of the URI is
 * used as a key ID when calling Android Keystore. If the master key doesn't exist, a fresh one is
 * generated. If the master key already exists but is unusable, a {@link KeyStoreException} is
 * thrown.
 *
 * <p>This class is thread-safe.
 *
 * @since 1.0.0
 */
public final class AndroidKeysetManager {
  private static final String TAG = AndroidKeysetManager.class.getSimpleName();
  private final KeysetWriter writer;
  private final Aead masterKey;

  @GuardedBy("this")
  private KeysetManager keysetManager;

  private AndroidKeysetManager(Builder builder) throws GeneralSecurityException, IOException {
    writer = builder.writer;
    masterKey = builder.masterKey;
    keysetManager = builder.keysetManager;
  }

  /**
   * A builder for {@link AndroidKeysetManager}.
   *
   * <p>This class is thread-safe.
   */
  public static final class Builder {
    private KeysetReader reader = null;
    private KeysetWriter writer = null;
    private String masterKeyUri = null;
    private Aead masterKey = null;
    private boolean useKeystore = true;
    private KeyTemplate keyTemplate = null;
    private KeyStore keyStore = null;

    @GuardedBy("this")
    private KeysetManager keysetManager;

    public Builder() {}

    /** Reads and writes the keyset from shared preferences. */
    public Builder withSharedPref(Context context, String keysetName, String prefFileName)
        throws IOException {
      if (context == null) {
        throw new IllegalArgumentException("need an Android context");
      }
      if (keysetName == null) {
        throw new IllegalArgumentException("need a keyset name");
      }
      reader = new SharedPrefKeysetReader(context, keysetName, prefFileName);
      writer = new SharedPrefKeysetWriter(context, keysetName, prefFileName);
      return this;
    }

    /**
     * Sets the master key URI.
     *
     * <p>Only master keys stored in Android Keystore is supported. The URI must start with {@code
     * android-keystore://}.
     */
    @RequiresApi(23)
    public Builder withMasterKeyUri(String val) {
      if (!val.startsWith(AndroidKeystoreKmsClient.PREFIX)) {
        throw new IllegalArgumentException(
            "key URI must start with " + AndroidKeystoreKmsClient.PREFIX);
      }
      if (!useKeystore) {
        throw new IllegalArgumentException(
            "cannot call withMasterKeyUri() after calling doNotUseKeystore()");
      }
      this.masterKeyUri = val;
      return this;
    }

    /**
     * If the keyset is not found or valid, generates a new one using {@code val}.
     *
     * @deprecated This method takes a KeyTemplate proto, which is an internal implementation
     *     detail. Please use the withKeyTemplate method that takes a {@link KeyTemplate} POJO.
     */
    @Deprecated
    public Builder withKeyTemplate(com.google.crypto.tink.proto.KeyTemplate val) {
      keyTemplate =
          KeyTemplate.create(
              val.getTypeUrl(), val.getValue().toByteArray(), fromProto(val.getOutputPrefixType()));
      return this;
    }

    /** If the keyset is not found or valid, generates a new one using {@code val}. */
    public Builder withKeyTemplate(KeyTemplate val) {
      keyTemplate = val;
      return this;
    }

    /**
     * Does not use Android Keystore which might not work well in some phones.
     *
     * <p><b>Warning:</b> When Android Keystore is disabled, keys are stored in cleartext. This
     * should be safe because they are stored in private preferences.
     *
     * @deprecated Android Keystore can be disabled by not setting a master key URI.
     */
    @Deprecated
    public Builder doNotUseKeystore() {
      masterKeyUri = null;
      useKeystore = false;
      return this;
    }

    /** This is for testing only */
    Builder withKeyStore(KeyStore val) {
      this.keyStore = val;
      return this;
    }

    /**
     * Builds and returns a new {@link AndroidKeysetManager} with the specified options.
     *
     * @throws IOException If a keyset is found but unusable.
     * @throws KeystoreException If a master key is found but unusable.
     * @throws GeneralSecurityException If cannot read an existing keyset or generate a new one.
     */
    public synchronized AndroidKeysetManager build() throws GeneralSecurityException, IOException {
      if (masterKeyUri != null) {
        masterKey = readOrGenerateNewMasterKey();
      }
      this.keysetManager = readOrGenerateNewKeyset();

      return new AndroidKeysetManager(this);
    }

    private Aead readOrGenerateNewMasterKey() throws GeneralSecurityException {
      if (!isAtLeastM()) {
        Log.w(TAG, "Android Keystore requires at least Android M");
        return null;
      }

      AndroidKeystoreKmsClient client;
      if (keyStore != null) {
        client = new AndroidKeystoreKmsClient.Builder().setKeyStore(keyStore).build();
      } else {
        client = new AndroidKeystoreKmsClient();
      }

      boolean existed = client.hasKey(masterKeyUri);
      if (!existed) {
        try {
          AndroidKeystoreKmsClient.generateNewAeadKey(masterKeyUri);
        } catch (GeneralSecurityException | ProviderException ex) {
          Log.w(TAG, "cannot use Android Keystore, it'll be disabled", ex);
          return null;
        }
      }

      try {
        return client.getAead(masterKeyUri);
      } catch (GeneralSecurityException | ProviderException ex) {
        // Throw the exception if the key exists but is unusable. We can't recover by generating a
        // new key because there might be existing encrypted data under the unusable key.
        // Users can provide a master key that is stored in StrongBox, which may throw a
        // ProviderException if there's any problem with it.
        if (existed) {
          throw new KeyStoreException(
              String.format("the master key %s exists but is unusable", masterKeyUri), ex);
        }
        // Otherwise swallow the exception if the key doesn't exist yet. We can recover by disabling
        // Keystore.
        Log.w(TAG, "cannot use Android Keystore, it'll be disabled", ex);
      }

      return null;
    }

    private KeysetManager readOrGenerateNewKeyset() throws GeneralSecurityException, IOException {
      try {
        return read();
      } catch (FileNotFoundException ex) {
        // Not found, handle below.
        if (Log.isLoggable(TAG, Log.INFO)) {
          Log.i(
              TAG, String.format("keyset not found, will generate a new one. %s", ex.getMessage()));
        }
      }

      // Not found.
      if (keyTemplate != null) {
        KeysetManager manager = KeysetManager.withEmptyKeyset().add(keyTemplate);
        int keyId = manager.getKeysetHandle().getKeysetInfo().getKeyInfo(0).getKeyId();
        manager = manager.setPrimary(keyId);
        if (masterKey != null) {
          manager.getKeysetHandle().write(writer, masterKey);
        } else {
          CleartextKeysetHandle.write(manager.getKeysetHandle(), writer);
        }
        return manager;
      }
      throw new GeneralSecurityException("cannot read or generate keyset");
    }

    private KeysetManager read() throws GeneralSecurityException, IOException {
      if (masterKey != null) {
        try {
          return KeysetManager.withKeysetHandle(KeysetHandle.read(reader, masterKey));
        } catch (InvalidProtocolBufferException | GeneralSecurityException ex) {
          // Swallow the exception and attempt to read the keyset in cleartext.
          // This edge case may happen when either
          //   - the keyset was generated on a pre M phone which is then upgraded to M or newer, or
          //   - the keyset was generated with Keystore being disabled, then Keystore is enabled.
          // By ignoring the security failure here, an adversary with write access to private
          // preferences can replace an encrypted keyset (that it cannot read or write) with a
          // cleartext value that it controls. This does not introduce new security risks because to
          // overwrite the encrypted keyset in private preferences of an app, said adversaries must
          // have the same privilege as the app, thus they can call Android Keystore to read or
          // write
          // the encrypted keyset in the first place.
          Log.w(TAG, "cannot decrypt keyset: ", ex);
        }
      }

      return KeysetManager.withKeysetHandle(CleartextKeysetHandle.read(reader));
    }
  }

  /** @return a {@link KeysetHandle} of the managed keyset */
  public synchronized KeysetHandle getKeysetHandle() throws GeneralSecurityException {
    return keysetManager.getKeysetHandle();
  }

  /**
   * Generates and adds a fresh key generated using {@code keyTemplate}, and sets the new key as the
   * primary key.
   *
   * @throws GeneralSecurityException if cannot find any {@link KeyManager} that can handle {@code
   *     keyTemplate}
   * @deprecated Please use {@link #add}. This method adds a new key and immediately promotes it to
   *     primary. However, when you do keyset rotation, you almost never want to make the new key
   *     primary, because old binaries don't know the new key yet.
   */
  @Deprecated
  public synchronized AndroidKeysetManager rotate(
      com.google.crypto.tink.proto.KeyTemplate keyTemplate) throws GeneralSecurityException {
    keysetManager = keysetManager.rotate(keyTemplate);
    write(keysetManager);
    return this;
  }

  /**
   * Generates and adds a fresh key generated using {@code keyTemplate}.
   *
   * @throws GeneralSecurityException if cannot find any {@link KeyManager} that can handle {@code
   *     keyTemplate}
   * @deprecated This method takes a KeyTemplate proto, which is an internal implementation detail.
   *     Please use the add method that takes a {@link KeyTemplate} POJO.
   */
  @GuardedBy("this")
  @Deprecated
  public synchronized AndroidKeysetManager add(com.google.crypto.tink.proto.KeyTemplate keyTemplate)
      throws GeneralSecurityException {
    keysetManager = keysetManager.add(keyTemplate);
    write(keysetManager);
    return this;
  }

  /**
   * Generates and adds a fresh key generated using {@code keyTemplate}.
   *
   * @throws GeneralSecurityException if cannot find any {@link KeyManager} that can handle {@code
   *     keyTemplate}
   */
  @GuardedBy("this")
  public synchronized AndroidKeysetManager add(KeyTemplate keyTemplate)
      throws GeneralSecurityException {
    keysetManager = keysetManager.add(keyTemplate);
    write(keysetManager);
    return this;
  }

  /**
   * Sets the key with {@code keyId} as primary.
   *
   * @throws GeneralSecurityException if the key is not found or not enabled
   */
  public synchronized AndroidKeysetManager setPrimary(int keyId) throws GeneralSecurityException {
    keysetManager = keysetManager.setPrimary(keyId);
    write(keysetManager);
    return this;
  }

  /**
   * Sets the key with {@code keyId} as primary.
   *
   * @throws GeneralSecurityException if the key is not found or not enabled
   * @deprecated use {@link setPrimary}
   */
  @Deprecated
  public synchronized AndroidKeysetManager promote(int keyId) throws GeneralSecurityException {
    return setPrimary(keyId);
  }

  /**
   * Enables the key with {@code keyId}.
   *
   * @throws GeneralSecurityException if the key is not found
   */
  public synchronized AndroidKeysetManager enable(int keyId) throws GeneralSecurityException {
    keysetManager = keysetManager.enable(keyId);
    write(keysetManager);
    return this;
  }

  /**
   * Disables the key with {@code keyId}.
   *
   * @throws GeneralSecurityException if the key is not found or it is the primary key
   */
  public synchronized AndroidKeysetManager disable(int keyId) throws GeneralSecurityException {
    keysetManager = keysetManager.disable(keyId);
    write(keysetManager);
    return this;
  }

  /**
   * Deletes the key with {@code keyId}.
   *
   * @throws GeneralSecurityException if the key is not found or it is the primary key
   */
  public synchronized AndroidKeysetManager delete(int keyId) throws GeneralSecurityException {
    keysetManager = keysetManager.delete(keyId);
    write(keysetManager);
    return this;
  }

  /**
   * Destroys the key material associated with the {@code keyId}.
   *
   * @throws GeneralSecurityException if the key is not found or it is the primary key
   */
  public synchronized AndroidKeysetManager destroy(int keyId) throws GeneralSecurityException {
    keysetManager = keysetManager.destroy(keyId);
    write(keysetManager);
    return this;
  }

  /** Returns whether Android Keystore is being used to wrap Tink keysets. */
  public synchronized boolean isUsingKeystore() {
    return shouldUseKeystore();
  }

  private void write(KeysetManager manager) throws GeneralSecurityException {
    try {
      if (shouldUseKeystore()) {
        manager.getKeysetHandle().write(writer, masterKey);
      } else {
        CleartextKeysetHandle.write(manager.getKeysetHandle(), writer);
      }
    } catch (IOException e) {
      throw new GeneralSecurityException(e);
    }
  }

  private boolean shouldUseKeystore() {
    return masterKey != null && isAtLeastM();
  }

  private static KeyTemplate.OutputPrefixType fromProto(OutputPrefixType outputPrefixType) {
    switch (outputPrefixType) {
      case TINK:
        return KeyTemplate.OutputPrefixType.TINK;
      case LEGACY:
        return KeyTemplate.OutputPrefixType.LEGACY;
      case RAW:
        return KeyTemplate.OutputPrefixType.RAW;
      case CRUNCHY:
        return KeyTemplate.OutputPrefixType.CRUNCHY;
      default:
        throw new IllegalArgumentException("Unknown output prefix type");
    }
  }

  @ChecksSdkIntAtLeast(api = Build.VERSION_CODES.M)
  private static boolean isAtLeastM() {
    return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M;
  }
}
