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
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import com.google.crypto.tink.KeysetWriter;
import com.google.crypto.tink.proto.EncryptedKeyset;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.subtle.Hex;
import java.io.IOException;

/**
 * A {@link KeysetWriter} that can write keysets to private shared preferences on Android.
 *
 * <p>We do not recommend new uses of this class. Instead, if you want to store a Tink keyset in
 * shared preferences, serialize the keyset using TinkProtoKeysetFormat, and write it hex-encoded
 * into your SharedPreferences manually.
 *
 * <p>For example, to write an encrypted keyset to the shared preferences, you can replace this:
 *
 * <pre>{@code
 * keysetHandle.write(
 *     new SharedPrefKeysetWriter(
 *         ApplicationProvider.getApplicationContext(), keysetName, null),
 *     keysetEncryptionAead);
 * }</pre>
 *
 * <p>with this:
 *
 * <pre>{@code
 * byte[] encryptedKeyset =
 *     TinkProtoKeysetFormat.serializeEncryptedKeyset(
 *         handle, keysetEncryptionAead, new byte[0]);
 * SharedPreferences.Editor editor =
 *     PreferenceManager.getDefaultSharedPreferences(
 *             ApplicationProvider.getApplicationContext().getApplicationContext())
 *         .edit();
 * boolean success = editor.putString(keysetName, Hex.encode(encryptedKeyset)).commit();
 * }</pre>
 *
 * <p>and to write an unencrypted keyset to the shared preferences, you can replace this:
 *
 * <pre>{@code
 * CleartextKeysetHandle.write(
 *     handle,
 *     new SharedPrefKeysetWriter(
 *         ApplicationProvider.getApplicationContext(), keysetName, null));
 * }</pre>
 *
 * <p>with this:
 *
 * <pre>{@code
 * byte[] serializedKeyset =
 *     TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
 * SharedPreferences.Editor editor =
 *     PreferenceManager.getDefaultSharedPreferences(
 *         ApplicationProvider.getApplicationContext().getApplicationContext())
 *     .edit();
 * boolean success = editor.putString(keysetName, Hex.encode(serializedKeyset)).commit();
 * }</pre>
 */
public final class SharedPrefKeysetWriter implements KeysetWriter {
  private final SharedPreferences.Editor editor;
  private final String keysetName;

  /**
   * Creates a {@link KeysetReader} that hex-encodes and writes keysets to the preference
   * name {@code keysetName} in the private shared preferences file {@code prefFileName}.
   *
   *<p>If {@code prefFileName} is null, uses the default shared preferences file.
   *
   * @throws IOException if cannot write the keyset
   * @throws IllegalArgumentException if {@code keysetName} is null
   */
  public SharedPrefKeysetWriter(Context context, String keysetName, String prefFileName) {
    if (keysetName == null) {
      throw new IllegalArgumentException("keysetName cannot be null");
    }
    this.keysetName = keysetName;

    Context appContext = context.getApplicationContext();
    if (prefFileName == null) {
      editor = PreferenceManager.getDefaultSharedPreferences(appContext).edit();
    } else {
      editor = appContext.getSharedPreferences(prefFileName, Context.MODE_PRIVATE).edit();
    }
  }

  @Override
  public void write(Keyset keyset) throws IOException {
    boolean success = editor.putString(keysetName, Hex.encode(keyset.toByteArray())).commit();
    if (!success) {
      throw new IOException("Failed to write to SharedPreferences");
    }
  }

  @Override
  public void write(EncryptedKeyset keyset) throws IOException {
    boolean success = editor.putString(keysetName, Hex.encode(keyset.toByteArray())).commit();
    if (!success) {
      throw new IOException("Failed to write to SharedPreferences");
    }
  }
}
