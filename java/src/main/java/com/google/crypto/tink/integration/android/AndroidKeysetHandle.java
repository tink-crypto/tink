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
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetReader;
import com.google.crypto.tink.KeysetWriter;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * A builder of {@link KeysetHandle} that supports reading/writing {@link
 * com.google.crypto.tink.proto.Keyset} to/from private shared preferences on Android.
 *
 * <p><b>Warning</b>: This class reads and writes to shared preferences, thus is best not to run on
 * the UI thread.
 *
 * <p>On Android M or newer, the keysets are encrypted with master keys generated and stored in <a
 * href="https://developer.android.com/training/articles/keystore.html">Android Keystore</a>.
 *
 * <p>Sample usage:
 *
 * <pre>{@code
 * KeyTemplate keyTemplate = AeadKeyTemplates.AES128_GCM;
 * String masterKeyUri = "android-keystore://my_master_key_id";
 * // Generate the master key if it does not exist.
 * AndroidKeystoreKmsClient.generateNewIfNotFound(masterKeyUri);
 * KeysetHandle keysetHandle = new AndroidKeysetHandle.Builder()
 *    .context(context)
 *    .prefName("my_pref_name")
 *    .masterKeyUri(masterKeyUri)
 *    .generateNewIfNotFound(keyTemplate)
 *    .build();
 * }</pre>
 *
 * <p>This will return a {@link KeysetHandle} from a keyset stored in the {@code my_pref_name}
 * preference name of the default shared preferences file. If the keyset is encrypted, it will be
 * decrypted using the {@code my_master_key_id} stored in Android Keystore. If the keyset is not
 * found a fresh one containing a single {@code AES128_GCM} key is generated.
 */
public final class AndroidKeysetHandle {
  private static final String TAG = AndroidKeysetHandle.class.getName();
  private final Context context;
  private final String prefFileName;
  private final String prefName;
  private final boolean useKeystore;
  private final String masterKeyUri;
  private final boolean generateNewIfNotFound;
  private final KeyTemplate keyTemplate;

  private AndroidKeysetHandle(Builder builder) throws GeneralSecurityException {
    context = builder.context;
    if (context == null) {
      throw new IllegalArgumentException(
          "need an Android context, please set it with Builder#context");
    }

    // If prefFileName is null, use the default shared preferences file.
    prefFileName = builder.prefFileName;

    prefName = builder.prefName;
    if (prefName == null) {
      throw new IllegalArgumentException(
          "need a preference name, please set it with Builder#prefName");
    }

    useKeystore = builder.useKeystore;

    masterKeyUri = builder.masterKeyUri;
    if (useKeystore && masterKeyUri == null) {
      throw new IllegalArgumentException(
          "need a master key URI, please set it with Builder#masterKeyUri");
    }

    generateNewIfNotFound = builder.generateNewIfNotFound;

    keyTemplate = builder.keyTemplate;
    if (generateNewIfNotFound && keyTemplate == null) {
      throw new IllegalArgumentException(
          "need a key template, please set it with Builder#generateNewIfNotFound");
    }
  }

  /**
   * A builder for {@link KeysetHandle} that supports reading/writing {@link
   * com.google.crypto.tink.proto.Keyset} to/from private shared preferences on Android.
   */
  public static final class Builder {
    public static final String DEFAULT_PREF_NAME = "TINK-KEYSET";
    private Context context = null;
    private String prefFileName = null;
    private String prefName = DEFAULT_PREF_NAME;
    private String masterKeyUri = null;
    private boolean useKeystore = true;
    private boolean generateNewIfNotFound = false;
    private KeyTemplate keyTemplate = null;

    public Builder() {}

    /** Sets the application context. */
    public Builder context(Context val) {
      context = val;
      return this;
    }

    /**
     * Sets the preferences file name.
     *
     * <p>If not set, uses the default shared preferences file.
     */
    public Builder prefFileName(String val) {
      prefFileName = val;
      return this;
    }

    /**
     * Sets the preference name.
     *
     * <p>If not set, uses {@link AndroidKeysetHandle.Builder#DEFAULT_PREF_NAME).
     */
    public Builder prefName(String val) {
      prefName = val;
      return this;
    }

    /**
     * Sets the master key URI.
     *
     * <p>Only master keys stored in Android Keystore is supported. The URI must start with {@code
     * android-keystore://}.
     */
    public Builder masterKeyUri(String val) {
      masterKeyUri = val;
      return this;
    }

    /**
     * Does not use Android Keystore, which might not work well in some phones.
     *
     * <p><b>Warning:</b> When Android Keystore is disabled, keys are stored in cleartext. This
     * should be safe because they are stored in private preferences.
     */
    public Builder doNotUseKeystore() {
      useKeystore = false;
      return this;
    }

    /** Whether should generate new keys with {@code val} if it is not found. */
    public Builder generateNewIfNotFound(KeyTemplate val) {
      generateNewIfNotFound = true;
      keyTemplate = val;
      return this;
    }

    /** @return a {@link KeysetHandle} with the specified options. */
    public KeysetHandle build() throws GeneralSecurityException, IOException {
      return new AndroidKeysetHandle(this).getKeysetHandle();
    }
  }

  private KeysetHandle getKeysetHandle() throws GeneralSecurityException, IOException {
    try {
      return readFromPref();
    } catch (IOException e) {
      // Not found, handle below.
      Log.i(TAG, "cannot read keyset from pref: " + e.toString());
    }

    // Not found.
    if (generateNewIfNotFound) {
      return generateNewAndWriteToPref();
    }
    throw new GeneralSecurityException("cannot obtain keyset handle");
  }

  private KeysetHandle readFromPref() throws GeneralSecurityException, IOException {
    KeysetReader reader = SharedPrefKeysetReader.withSharedPref(context, prefFileName, prefName);
    if (shouldUseKeystore()) {
      try {
        Aead masterKey = new AndroidKeystoreKmsClient().getAead(masterKeyUri);
        return KeysetHandle.read(reader, masterKey);
      } catch (InvalidProtocolBufferException e) {
        // This edge case happens either when
        //   - pre-M users upgraded to M or newer, or
        //   - keystore was disabled then reenabled.
        // Let's log and try to read the keyset in cleartext.
        Log.i(TAG, "cannot decrypt keyset: " + e.toString());
      }
    }
    return CleartextKeysetHandle.read(reader);
  }

  private KeysetHandle generateNewAndWriteToPref() throws GeneralSecurityException, IOException {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(keyTemplate);
    KeysetWriter writer = SharedPrefKeysetWriter.withSharedPref(context, prefFileName, prefName);
    if (shouldUseKeystore()) {
      Aead masterKey = new AndroidKeystoreKmsClient().getAead(masterKeyUri);
      keysetHandle.write(writer, masterKey);
    } else {
      CleartextKeysetHandle.write(keysetHandle, writer);
    }
    return keysetHandle;
  }

  private boolean shouldUseKeystore() {
    return useKeystore && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M;
  }
}
