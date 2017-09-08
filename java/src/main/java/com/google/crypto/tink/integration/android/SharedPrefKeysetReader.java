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
import com.google.crypto.tink.BinaryKeysetReader;
import com.google.crypto.tink.KeysetReader;
import com.google.crypto.tink.subtle.Hex;
import java.io.IOException;

/** A {@link KeysetReader} that can read keysets from private shared preferences on Android. */
public final class SharedPrefKeysetReader {
  /**
   * Creates a {@link KeysetReader} that reads and hex-decodes keysets from the preference name
   * {@code prefName} in the private shared preferences file {@code fileName}.
   *
   * <p>If {@code fileName} is null, uses the default shared preferences file.
   *
   * @throws IOException if cannot read the keyset
   * @throws IllegalArgumentException if {@code prefName} is null
   */
  public static KeysetReader withSharedPref(Context context, String fileName, String prefName)
      throws IOException {
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

    try {
      String keysetHex = sharedPreferences.getString(prefName, null /* default value */);
      if (keysetHex == null) {
        throw new IOException(
            String.format("can't read keyset; the pref value %s does not exist", prefName));
      }
      return BinaryKeysetReader.withBytes(Hex.decode(keysetHex));
    } catch (ClassCastException e) {
      throw new IOException(
          String.format("can't read keyset; the pref value %s is not a string", prefName), e);
    }
  }
}
