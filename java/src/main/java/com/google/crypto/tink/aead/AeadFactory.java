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

package com.google.crypto.tink.aead;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.subtle.Bytes;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

/**
 * Static methods for obtaining {@link Aead} instances.
 *
 * <h3>Usage</h3>
 *
 * <pre>{@code
 * KeysetHandle keysetHandle = ...;
 * Aead aead = AeadFactory.getPrimitive(keysetHandle);
 * byte[] plaintext = ...;
 * byte[] aad = ...;
 * byte[] ciphertext = aead.encrypt(plaintext, aad);
 * }</pre>
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To encrypt a plaintext,
 * it uses the primary key in the keyset, and prepends to the ciphertext a certain prefix associated
 * with the primary key. To decrypt, the primitive uses the prefix of the ciphertext to efficiently
 * select the right key in the set. If the keys associated with the prefix do not work, the
 * primitive tries all keys with {@link com.google.crypto.tink.proto.OutputPrefixType#RAW}.
 *
 * @since 1.0.0
 */
public final class AeadFactory {
  private static final Logger logger = Logger.getLogger(AeadFactory.class.getName());

  /**
   * @return a Aead primitive from a {@code keysetHandle}.
   * @throws GeneralSecurityException
   */
  public static Aead getPrimitive(KeysetHandle keysetHandle) throws GeneralSecurityException {
    return getPrimitive(keysetHandle, /* keyManager= */ null);
  }

  /**
   * @return a Aead primitive from a {@code keysetHandle} and a custom {@code keyManager}.
   * @throws GeneralSecurityException
   */
  public static Aead getPrimitive(KeysetHandle keysetHandle, final KeyManager<Aead> keyManager)
      throws GeneralSecurityException {
    final PrimitiveSet<Aead> primitives = Registry.getPrimitives(keysetHandle, keyManager);
    return new Aead() {
      @Override
      public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
          throws GeneralSecurityException {
        return Bytes.concat(
            primitives.getPrimary().getIdentifier(),
            primitives.getPrimary().getPrimitive().encrypt(plaintext, associatedData));
      }

      @Override
      public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
          throws GeneralSecurityException {
        if (ciphertext.length > CryptoFormat.NON_RAW_PREFIX_SIZE) {
          byte[] prefix = Arrays.copyOfRange(ciphertext, 0, CryptoFormat.NON_RAW_PREFIX_SIZE);
          byte[] ciphertextNoPrefix =
              Arrays.copyOfRange(ciphertext, CryptoFormat.NON_RAW_PREFIX_SIZE, ciphertext.length);
          List<PrimitiveSet.Entry<Aead>> entries = primitives.getPrimitive(prefix);
          for (PrimitiveSet.Entry<Aead> entry : entries) {
            try {
              return entry.getPrimitive().decrypt(ciphertextNoPrefix, associatedData);
            } catch (GeneralSecurityException e) {
              logger.info("ciphertext prefix matches a key, but cannot decrypt: " + e.toString());
              continue;
            }
          }
        }

        // Let's try all RAW keys.
        List<PrimitiveSet.Entry<Aead>> entries = primitives.getRawPrimitives();
        for (PrimitiveSet.Entry<Aead> entry : entries) {
          try {
            return entry.getPrimitive().decrypt(ciphertext, associatedData);
          } catch (GeneralSecurityException e) {
            continue;
          }
        }
        // nothing works.
        throw new GeneralSecurityException("decryption failed");
      }
    };
  }
}
