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
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetManager;
import com.google.crypto.tink.KeysetReader;
import com.google.crypto.tink.KeysetWriter;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
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
 * String masterKeyUri = "android-keystore://my_master_key_id";
 * AndroidKeysetManager manager = AndroidKeysetManager.Builder()
 *    .withSharedPref(getApplicationContext(), "my_keyset_name", "my_pref_file_name")
 *    .withKeyTemplate(AesGcmHkfStreamingKeyManager.aes128GcmHkdf4KBTemplate())
 *    .withMasterKeyUri(masterKeyUri)
 *    .build();
 * StreamingAead streamingAead = manager.getKeysetHandle().getPrimitive(StreamingAead.class);
 * }</pre>
 *
 * <p>This will read a keyset stored in the {@code my_keyset_name} preference of the {@code
 * my_pref_file_name} preferences file. If the preference file name is null, it uses the default
 * preferences file.
 *
 * <p>Alternatively, you can provide a custom reader/writer with
 * {@link AndroidKeysetManager.Builder#withKeysetReader} and {@link AndroidKeysetManager.Builder#withKeysetWriter},
 * which will be used for managing keyset.
 *
 * <p>If the keyset is not found or invalid, and a valid {@link KeyTemplate} is set with {@link
 * AndroidKeysetManager.Builder#withKeyTemplate}, a fresh keyset is generated and is written to the
 * {@code my_keyset_name} preference of the {@code my_pref_file_name} shared preferences file.
 *
 * <p>On Android M or newer and if a master key URI is set with {@link
 * AndroidKeysetManager.Builder#withMasterKeyUri}, the keyset is encrypted with a master key
 * generated and stored in <a
 * href="https://developer.android.com/training/articles/keystore.html">Android Keystore</a>. When
 * Tink cannot decrypt the keyset it would assume that it is not encrypted.
 *
 * <p>The master key URI must start with {@code android-keystore://}. If the master key doesn't
 * exist, a fresh one is generated.
 *
 * <p>Usage of Android Keystore can be disabled with {@link
 * AndroidKeysetManager.Builder#doNotUseKeystore}. Android Keystore on certain devices is broken.
 * Tink runs a self-test to detect such problems and disable Android Keystore accordingly. Users can
 * check whether Android Keystore is in use with {@link #isUsingKeystore}.
 *
 * <p>On Android L or older, or when either Android Keystore is disabled or the master key URI is
 * not set, the keyset will be stored in cleartext in private preferences which, thanks to the
 * security of the Android framework, no other apps can read or write.
 *
 * <p>The resulting manager supports all operations supported by {@link KeysetManager}. For example
 * to rotate the keyset, one can do:
 *
 * <pre>{@code
 * manager.rotate(AesGcmHkfStreamingKeyManager.aes128GcmHkdf1MBTemplate());
 * }</pre>
 *
 * <p>All operations that manipulate the keyset would automatically persist the new keyset to
 * permanent storage.
 *
 * @since 1.0.0
 */
public final class AndroidKeysetManager {
  private static final String TAG = AndroidKeysetManager.class.getSimpleName();
  private final KeysetReader reader;
  private final KeysetWriter writer;
  private final boolean useKeystore;
  private final Aead masterKey;
  private final KeyTemplate keyTemplate;

  @GuardedBy("this")
  private KeysetManager keysetManager;

  private AndroidKeysetManager(Builder builder) throws GeneralSecurityException, IOException {
    reader = builder.reader;
    if (reader == null) {
      throw new IllegalArgumentException("need to specify where to read the keyset from with " +
              "Builder#withSharedPref or Builder#withKeysetReader");
    }

    writer = builder.writer;
    if (writer == null) {
      throw new IllegalArgumentException("need to specify where to write the keyset to with " +
              "Builder#withSharedPref or Builder#withKeysetWriter");
    }

    if (builder.useKeystore && builder.masterKeyUri == null) {
      throw new IllegalArgumentException(
          "need a master key URI, please set it with Builder#masterKeyUri");
    }
    useKeystore = builder.useKeystore && verifyAndroidKeystore();

    if (shouldUseKeystore()) {
      masterKey = AndroidKeystoreKmsClient.getOrGenerateNewAeadKey(builder.masterKeyUri);
    } else {
      masterKey = null;
    }

    keyTemplate = builder.keyTemplate;
    keysetManager = readOrGenerateNewKeyset();
  }

  /** A builder for {@link AndroidKeysetManager}. */
  public static final class Builder {
    private KeysetReader reader = null;
    private KeysetWriter writer = null;
    private String masterKeyUri = null;
    private boolean useKeystore = true;
    private KeyTemplate keyTemplate = null;

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

    /** Reads the keyset from provided reader. */
    public Builder withKeysetReader(KeysetReader reader) {
      this.reader = reader;
      return this;
    }

    /** Writes the keyset to provided writer. */
    public Builder withKeysetWriter(KeysetWriter writer) {
      this.writer = writer;
      return this;
    }

    /**
     * Sets the master key URI.
     *
     * <p>Only master keys stored in Android Keystore is supported. The URI must start with {@code
     * android-keystore://}.
     */
    public Builder withMasterKeyUri(String val) {
      if (!val.startsWith(AndroidKeystoreKmsClient.PREFIX)) {
        throw new IllegalArgumentException(
            "key URI must start with " + AndroidKeystoreKmsClient.PREFIX);
      }
      masterKeyUri = val;
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
     */
    public Builder doNotUseKeystore() {
      useKeystore = false;
      return this;
    }

    /** @return a {@link KeysetHandle} with the specified options. */
    public AndroidKeysetManager build() throws GeneralSecurityException, IOException {
      return new AndroidKeysetManager(this);
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

  /** Returns whether this keyset manager is wrapping keys with Android Keystore. */
  public synchronized boolean isUsingKeystore() {
    return shouldUseKeystore();
  }

  private KeysetManager readOrGenerateNewKeyset() throws GeneralSecurityException, IOException {
    try {
      return read();
    } catch (IOException e) {
      // Not found, handle below.
      Log.w(TAG, "cannot read keyset: " + e);
    }

    // Not found.
    if (keyTemplate != null) {
      KeysetManager manager = KeysetManager.withEmptyKeyset().add(keyTemplate);
      int keyId = manager.getKeysetHandle().getKeysetInfo().getKeyInfo(0).getKeyId();
      manager = manager.setPrimary(keyId);
      write(manager);
      return manager;
    }
    throw new GeneralSecurityException("cannot obtain keyset handle");
  }

  private KeysetManager read() throws GeneralSecurityException, IOException {
    if (shouldUseKeystore()) {
      try {
        return KeysetManager.withKeysetHandle(KeysetHandle.read(reader, masterKey));
      } catch (InvalidProtocolBufferException | GeneralSecurityException e) {
        // This edge case happens when
        //   - the keyset was generated on a pre M phone which is then upgraded to M or newer, or
        //   - the keyset was generated with Keystore being disabled, then Keystore is enabled.
        // By ignoring the security failure here, an adversary with write access to private
        // preferences can replace an encrypted keyset (that it cannot read or write) with a
        // cleartext value that it controls. This does not introduce new security risks because to
        // overwrite the encrypted keyset in private preferences of an app, said adversaries must
        // have the same privilege as the app, thus they can call Android Keystore to read or write
        // the encrypted keyset in the first place.
        // So it's okay to ignore the failure and try to read the keyset in cleartext.
        Log.w(TAG, "cannot decrypt keyset: " + e);
      }
    }
    KeysetHandle handle = CleartextKeysetHandle.read(reader);
    if (shouldUseKeystore()) {
      // Opportunistically encrypt the keyset to avoid further fallback to cleartext.
      handle.write(writer, masterKey);
    }
    return KeysetManager.withKeysetHandle(handle);
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
    return useKeystore && isAtLeastM();
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

  private static boolean isAtLeastM() {
    return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M;
  }

  /**
   * Does a self-test to verify whether we can rely on Android Keystore, which is broken in many
   * devices.
   */
  private static boolean verifyAndroidKeystore() {
    if (!isAtLeastM()) {
      return false;
    }

    try {
      String randomKeyId =
          AndroidKeystoreKmsClient.PREFIX
              + new String(Random.randBytes(16), Charset.forName("UTF-8"));
      Aead aead = AndroidKeystoreKmsClient.getOrGenerateNewAeadKey(randomKeyId);

      // Empty message.
      // Empty aad.
      byte[] message = new byte[0];
      byte[] aad = new byte[0];
      byte[] ciphertext = aead.encrypt(message, aad);
      byte[] decrypted = aead.decrypt(ciphertext, aad);
      if (decrypted.length != 0) {
        Log.w(
            TAG,
            "cannot use Android Keystore: encryption/decryption of empty message and empty aad"
                + " returns incorrect results");
        return false;
      }

      // Non-empty message.
      // Empty aad.
      message = Random.randBytes(10);
      aad = new byte[0];
      ciphertext = aead.encrypt(message, aad);
      decrypted = aead.decrypt(ciphertext, aad);
      if (!Hex.encode(decrypted).equals(Hex.encode(message))) {
        Log.w(
            TAG,
            "cannot use Android Keystore: encryption/decryption of non-empty message and empty"
                + " aad returns incorrect results");
        return false;
      }

      // Non-empty message.
      // Non-empty aad.
      message = Random.randBytes(10);
      aad = Random.randBytes(10);
      ciphertext = aead.encrypt(message, aad);
      decrypted = aead.decrypt(ciphertext, aad);
      if (!Hex.encode(decrypted).equals(Hex.encode(message))) {
        Log.w(
            TAG,
            "cannot use Android Keystore: encryption/decryption of non-empty message and"
                + " non-empty aad returns incorrect results");
        return false;
      }

      AndroidKeystoreKmsClient.delete(randomKeyId);

      return true;
    } catch (Exception ex) {
      Log.w(TAG, "cannot use Android Keystore: " + ex);
    }

    return false;
  }
}
