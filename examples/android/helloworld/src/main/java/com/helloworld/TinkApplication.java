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

package com.helloworld;

import android.app.Application;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.Config;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.integration.android.AndroidKeysetManager;
import java.io.IOException;
import java.security.GeneralSecurityException;

/** A custom application that initializes the Tink runtime at application startup. */
public class TinkApplication extends Application {
  private static final String TAG = TinkApplication.class.toString();
  private static final String PREF_FILE_NAME = "hello_world_pref";
  private static final String TINK_KEYSET_NAME = "hello_world_keyset";
  private static final String MASTER_KEY_URI = "android-keystore://hello_world_master_key";
  public Aead aead;

  @Override
  public final void onCreate() {
    super.onCreate();
    try {
      Config.register(TinkConfig.TINK_1_0_0);
      aead = getOrGenerateNewKeysetHandle().getPrimitive(Aead.class);
    } catch (GeneralSecurityException | IOException e) {
      throw new RuntimeException(e);
    }
  }

  private KeysetHandle getOrGenerateNewKeysetHandle() throws IOException, GeneralSecurityException {
    return new AndroidKeysetManager.Builder()
        .withSharedPref(getApplicationContext(), TINK_KEYSET_NAME, PREF_FILE_NAME)
        .withKeyTemplate(AeadKeyTemplates.AES256_GCM)
        .withMasterKeyUri(MASTER_KEY_URI)
        .build()
        .getKeysetHandle();
  }
}
