// Copyright 2017 Google Inc.
// //
// // Licensed under the Apache License, Version 2.0 (the "License");
// // you may not use this file except in compliance with the License.
// // You may obtain a copy of the License at
// //
// //      http://www.apache.org/licenses/LICENSE-2.0
// //
// // Unless required by applicable law or agreed to in writing, software
// // distributed under the License is distributed on an "AS IS" BASIS,
// // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// // See the License for the specific language governing permissions and
// // limitations under the License.
// //
// ////////////////////////////////////////////////////////////////////////////////

package com.google.cloud.crypto.tink.subtle;

import com.google.cloud.crypto.tink.Aead;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public final class AesGcmJce implements Aead {

  // All instances of this class use a 12 byte IV and a 16 byte tag.
  private static int IV_SIZE_IN_BYTES = 12;
  private static int TAG_SIZE_IN_BYTES = 16;

  private final SecretKeySpec keySpec;

  public AesGcmJce(final byte[] key) {
    keySpec = new SecretKeySpec(key, "AES");
  }

  private Cipher instance() throws NoSuchAlgorithmException, NoSuchPaddingException {
    return Cipher.getInstance("AES/GCM/NoPadding");
  }

  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] aad)
      throws GeneralSecurityException {
    // Check that ciphertext is not longer than the max. size of a Java array.
    if (plaintext.length > Integer.MAX_VALUE - IV_SIZE_IN_BYTES - TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("Plaintext too long");
    }
    byte[] ciphertext = new byte[IV_SIZE_IN_BYTES + plaintext.length + TAG_SIZE_IN_BYTES];
    byte[] iv = Random.randBytes(IV_SIZE_IN_BYTES);
    System.arraycopy(iv, 0, ciphertext, 0, IV_SIZE_IN_BYTES);

    Cipher cipher = instance();
    GCMParameterSpec params = new GCMParameterSpec(8 * TAG_SIZE_IN_BYTES, iv);
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, params);
    cipher.updateAAD(aad);
    int written = cipher.doFinal(plaintext, 0, plaintext.length, ciphertext, IV_SIZE_IN_BYTES);
    return ciphertext;
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] aad)
      throws GeneralSecurityException {
    if (ciphertext.length < IV_SIZE_IN_BYTES + TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    GCMParameterSpec params =
        new GCMParameterSpec(8 * TAG_SIZE_IN_BYTES, ciphertext, 0, IV_SIZE_IN_BYTES);
    Cipher cipher = instance();
    cipher.init(Cipher.DECRYPT_MODE, keySpec, params);
    cipher.updateAAD(aad);
    return cipher.doFinal(
        ciphertext, IV_SIZE_IN_BYTES, ciphertext.length - IV_SIZE_IN_BYTES);
  }

  /**
   * TODO(bleichen): Would it be possible to implement this in AEAD or some generic sub-class
   *   of this? Is there a simpler implementation using lambda expressions?
   *   Shouldn't the caller be responsible to decide how these tasks are scheduled,
   *   i.e. shouldn't the caller be able to add the task to a threadpool?
   * TODO(bleichen): Do we have to clone the inputs or can we assume that the inputs remain
   *   unchanged until the asynchronous encryption terminates?
   */
  @Override
  public Future<byte[]> asyncEncrypt(final byte[] plaintext, final byte[] aad)
      throws GeneralSecurityException {
    return Executors.newSingleThreadExecutor().submit(() -> encrypt(plaintext, aad));
  }

  @Override
  public Future<byte[]> asyncDecrypt(final byte[] ciphertext, final byte[] aad)
      throws GeneralSecurityException {
    return Executors.newSingleThreadExecutor().submit(() -> decrypt(ciphertext, aad));
  }
};
