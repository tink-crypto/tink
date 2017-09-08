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

/** A {@link KeysetWriter} that can write keysets to private shared preferences on Android. */
public final class SharedPrefKeysetWriter implements KeysetWriter {
  private final SharedPreferences.Editor editor;
  private final String prefName;

  /**
   * Creates a {@link KeysetReader} that hex-encodes and writes keysets to the preference name
   * {@code prefName} in the private shared preferences file {@code fileName}.
   *
   * <p>If {@code fileName} is null, uses the default shared preferences file.
   *
   * @throws IOException if cannot write the keyset
   * @throws IllegalArgumentException if {@code prefName} is null
   */
  public static KeysetWriter withSharedPref(Context context, String fileName, String prefName) {
    if (prefName == null) {
      throw new IllegalArgumentException("prefName cannot be null");
    }

    Context appContext = context.getApplicationContext();
    SharedPreferences sharedPreferences;
    if (fileName == null) {
      sharedPreferences = PreferenceManager.getDefaultSharedPreferences(appContext);
    } else {
      sharedPreferences = appContext.getSharedPreferences(fileName, Context.MODE_PRIVATE);
    }

    return new SharedPrefKeysetWriter(sharedPreferences.edit(), prefName);
  }

  private SharedPrefKeysetWriter(SharedPreferences.Editor editor, String prefName) {
    this.editor = editor;
    this.prefName = prefName;
  }

  @Override
  public void write(Keyset keyset) throws IOException {
    editor.putString(prefName, Hex.encode(keyset.toByteArray())).apply();
  }

  @Override
  public void write(EncryptedKeyset keyset) throws IOException {
    editor.putString(prefName, Hex.encode(keyset.toByteArray())).apply();
  }
}
