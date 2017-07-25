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
import android.os.Build.VERSION_CODES;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.subtle.AesGcmJce;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import javax.crypto.SecretKey;

/**
 * An {@link Aead} that forwards encryption/decryption requests to an {@code AES-GCM} key in
 * <a href="https://developer.android.com/training/articles/keystore.html">Android Keystore</a>.
 *
 * <p>This class requires Android M or newer.
 */
@TargetApi(VERSION_CODES.M)
public final class AndroidKeystoreAesGcm implements Aead {

  private final Aead aead;

  public AndroidKeystoreAesGcm(String keyId) throws GeneralSecurityException, IOException {
    KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
    keyStore.load(null /* param */);
    SecretKey secretKey = (SecretKey) keyStore.getKey(keyId, null /* password */);
    aead = new AesGcmJce(secretKey);
  }

  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] aad)
      throws GeneralSecurityException {
    return aead.encrypt(plaintext, aad);
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] aad)
      throws GeneralSecurityException {
    return aead.decrypt(ciphertext, aad);
  }
}
