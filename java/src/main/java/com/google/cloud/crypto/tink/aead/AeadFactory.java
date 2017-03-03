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

package com.google.cloud.crypto.tink.aead;

import com.google.cloud.crypto.tink.Aead;
import com.google.cloud.crypto.tink.CryptoFormat;
import com.google.cloud.crypto.tink.KeyManager;
import com.google.cloud.crypto.tink.KeysetHandle;
import com.google.cloud.crypto.tink.PrimitiveSet;
import com.google.cloud.crypto.tink.Registry;
import com.google.cloud.crypto.tink.subtle.IndCpaCipher;
import com.google.cloud.crypto.tink.subtle.Util;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.security.GeneralSecurityException;

/**
 * AeadFactory allows obtaining a primitive from a {@code KeysetHandle}.
 *
 * AeadFactory gets primitives from the {@code Registry}. The factory allows initalizing the
 * {@code Registry} with native key types and their managers that Tink supports out of the box.
 * These key types are divided in two groups:
 *   - standard: secure and safe to use in new code. Over time, with new developments in
 *               cryptanalysis and computing power, some standard key types might become legacy.
 *   - legacy: deprecated and insecure or obsolete, should not be used in new code. Existing users
 *             should upgrade to one of the standard key types.
 * This divison allows for gradual retiring insecure or obsolete key types.
 *
 * For example, here is how one can obtain and use a Aead primitive:
 * <pre>   {@code
 *   KeysetHandle keysetHandle = ...;
 *   AeadFactory.registerStandardKeyTypes();
 *   Aead aead = AeadFactory.getPrimitive(keysetHandle);
 *   byte[] plaintext = ...;
 *   byte[] aad = ...;
 *   byte[] ciphertext = aead.encrypt(plaintext, aad);
 *  }</pre>
 */
public final class AeadFactory {
  /**
   * Safe to use Aead key types.
   */
  private static final Map<String, KeyManager<Aead>> STANDARD_KEY_TYPES;

  /**
   * Deprecated Aead key types, should not be used in new code.
   */
  private static final Map<String, KeyManager<Aead>> LEGACY_KEY_TYPES;

  static {
    Map<String, KeyManager<Aead>> standard = new HashMap<String, KeyManager<Aead>>();
    standard.put(
        "type.googleapis.com/google.cloud.crypto.tink.AesCtrHmacAeadKey",
        new AesCtrHmacAeadKeyManager());
    standard.put(
        "type.googleapis.com/google.cloud.crypto.tink.KmsEnvelopeAeadKey",
        new KmsEnvelopeAeadKeyManager());
    standard.put(
        "type.googleapis.com/google.cloud.crypto.tink.AesGcmKey",
        new AesGcmKeyManager());
    STANDARD_KEY_TYPES = Collections.unmodifiableMap(standard);

    Map<String, KeyManager<Aead>> legacy = new HashMap<String, KeyManager<Aead>>();
    LEGACY_KEY_TYPES = Collections.unmodifiableMap(legacy);
  }

  /**
   * Registers standard Aead key types and their managers with the {@code Registry}.
   * @throws GeneralSecurityException
   */
  public static void registerStandardKeyTypes() throws GeneralSecurityException {
    for (Entry<String, KeyManager<Aead>> entry : STANDARD_KEY_TYPES.entrySet()) {
      Registry.INSTANCE.registerKeyManager(entry.getKey(), entry.getValue());
    }
  }

  /**
   * Registers legacy Aead key types and their managers with the {@code Registry}.
   * @throws GeneralSecurityException
   */
  public static void registerLegacyKeyTypes() throws GeneralSecurityException {
    for (Entry<String, KeyManager<Aead>> entry : LEGACY_KEY_TYPES.entrySet()) {
      Registry.INSTANCE.registerKeyManager(entry.getKey(), entry.getValue());
    }
  }

  /**
   * @returns a Aead primitive from a {@code keysetHandle}.
   * @throws GeneralSecurityException
   */
  public static Aead getPrimitive(final KeysetHandle keysetHandle)
      throws GeneralSecurityException {
    return getPrimitive(keysetHandle, null /* keyManager */);
  }

  /**
   * @returns a Aead primitive from a {@code keysetHandle} and a custom {@code keyManager}.
   * @throws GeneralSecurityException
   */
  public static Aead getPrimitive(final KeysetHandle keysetHandle,
      final KeyManager<Aead> keyManager)
      throws GeneralSecurityException {
    PrimitiveSet<Aead> primitives =
        Registry.INSTANCE.getPrimitives(keysetHandle, keyManager);
    return new Aead() {
      @Override
      public byte[] encrypt(final byte[] plaintext, final byte[] aad)
          throws GeneralSecurityException {
        return Util.concat(
            primitives.getPrimary().getIdentifier(),
            primitives.getPrimary().getPrimitive().encrypt(plaintext, aad));
      }

      @Override
      public byte[] decrypt(final byte[] ciphertext, final byte[] aad)
          throws GeneralSecurityException {
        if (ciphertext.length > CryptoFormat.NON_RAW_PREFIX_SIZE) {
          byte[] prefix = Arrays.copyOfRange(ciphertext, 0, CryptoFormat.NON_RAW_PREFIX_SIZE);
          byte[] ciphertextNoPrefix = Arrays.copyOfRange(
              ciphertext,
              CryptoFormat.NON_RAW_PREFIX_SIZE,
              ciphertext.length);
          List<PrimitiveSet<Aead>.Entry<Aead>> entries = primitives.getPrimitive(prefix);
          for (PrimitiveSet<Aead>.Entry<Aead> entry : entries) {
            try {
              return entry.getPrimitive().decrypt(ciphertextNoPrefix, aad);
            } catch (GeneralSecurityException e) {
              continue;
            }
          }
        }

        // Let's try all RAW keys.
        List<PrimitiveSet<Aead>.Entry<Aead>> entries = primitives.getRawPrimitives();
        for (PrimitiveSet<Aead>.Entry<Aead> entry : entries) {
          try {
            return entry.getPrimitive().decrypt(ciphertext, aad);
          } catch (GeneralSecurityException e) {
            continue;
          }
        }
        // nothing works.
        throw new GeneralSecurityException("decrypted failed");
      }

      @Override
      public Future<byte[]> asyncEncrypt(byte[] plaintext, byte[] aad)
          throws GeneralSecurityException {
        throw new GeneralSecurityException("Not Implemented Yet");
      }

      @Override
      public Future<byte[]> asyncDecrypt(byte[] ciphertext, byte[] aad)
          throws GeneralSecurityException {
        throw new GeneralSecurityException("Not Implemented Yet");
      }
    };
  }
}
