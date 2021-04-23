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
import com.google.crypto.tink.KeysetReader;
import com.google.crypto.tink.proto.EncryptedKeyset;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.subtle.Hex;
import com.google.protobuf.ExtensionRegistryLite;
import java.io.CharConversionException;
import java.io.FileNotFoundException;
import java.io.IOException;

/**
 * A {@link KeysetReader} that can read keysets from private shared preferences on Android.
 *
 * @since 1.0.0
 */
public final class SharedPrefKeysetReader implements KeysetReader {
  private final SharedPreferences sharedPreferences;
  private final String keysetName;

  /**
   * Creates a {@link KeysetReader} that reads and hex-decodes keysets from the preference
   * name {@code keysetName} in the private shared preferences file {@code prefFilename}.
   *
   *<p>If {@code prefFilename} is null, uses the default shared preferences file.
   *
   * @throws IOException if cannot read the keyset
   * @throws IllegalArgumentException if {@code keysetName} is null
   */
  public SharedPrefKeysetReader(Context context, String keysetName, String prefFilename)
      throws IOException {
    if (keysetName == null) {
      throw new IllegalArgumentException("keysetName cannot be null");
    }
    this.keysetName = keysetName;

    Context appContext = context.getApplicationContext();
    if (prefFilename == null) {
      sharedPreferences = PreferenceManager.getDefaultSharedPreferences(appContext);
    } else {
      sharedPreferences = appContext.getSharedPreferences(
        prefFilename, Context.MODE_PRIVATE);
    }
  }

  /**
   * Creates a {@link KeysetReader} that reads and hex-decodes keysets from the preference
   * name {@code keysetName} in given shared preferences object.
   *
   * @throws IOException if cannot read the keyset
   * @throws IllegalArgumentException if {@code keysetName} or {@code sharedPreferences} is null
   */
  public SharedPrefKeysetReader(String keysetName, SharedPreferences sharedPreferences)
          throws IOException {
    if (keysetName == null) {
      throw new IllegalArgumentException("keysetName cannot be null");
    }
    if (sharedPreferences == null) {
      throw new IllegalArgumentException("sharedPreferences cannot be null");
    }
    this.keysetName = keysetName;
    this.sharedPreferences = sharedPreferences;
  }

  @SuppressWarnings("UnusedException")
  private byte[] readPref() throws IOException {
    try {
      String keysetHex = sharedPreferences.getString(keysetName, null /* default value */);
      if (keysetHex == null) {
        throw new FileNotFoundException(
            String.format("can't read keyset; the pref value %s does not exist", keysetName));
      }
      return Hex.decode(keysetHex);
    } catch (ClassCastException | IllegalArgumentException ex) {
      // The original exception is swallowed to prevent leaked key material.
      throw new CharConversionException(
          String.format(
              "can't read keyset; the pref value %s is not a valid hex string", keysetName));
    }
  }

  @Override
  public Keyset read() throws IOException {
    return Keyset.parseFrom(readPref(), ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public EncryptedKeyset readEncrypted() throws IOException {
    return EncryptedKeyset.parseFrom(readPref(), ExtensionRegistryLite.getEmptyRegistry());
  }
}
