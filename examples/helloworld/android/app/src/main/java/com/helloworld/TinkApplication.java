package com.helloworld;

import android.app.Application;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.Config;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadFactory;
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
      aead = AeadFactory.getPrimitive(getOrGenerateNewKeysetHandle());
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
