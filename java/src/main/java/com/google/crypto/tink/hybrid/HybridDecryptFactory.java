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
package com.google.crypto.tink.hybrid;

import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.Registry;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.logging.Logger;

/**
 * Static methods for obtaining {@link HybridDecrypt} instances.
 *
 * <h3>Usage</h3>
 *
 * <pre>{@code
 * KeysetHandle keysetHandle = ...;
 * HybridDecrypt hybridDecrypt = HybridDecryptFactory.getPrimitive(keysetHandle);
 * byte[] ciphertext = ...;
 * byte[] contextInfo = ...;
 * byte[] plaintext = hybridDecrypt.decrypt(ciphertext, contextInfo);
 * }</pre>
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To decrypt, the
 * primitive uses the prefix of the ciphertext to efficiently select the right key in the set. If
 * the keys associated with the prefix do not work, the primitive tries all keys with {@link
 * com.google.crypto.tink.proto.OutputPrefixType#RAW}.
 *
 * @since 1.0.0
 */
public final class HybridDecryptFactory {
  private static final Logger logger = Logger.getLogger(HybridDecryptFactory.class.getName());

  /**
   * @return a HybridDecrypt primitive from a {@code keysetHandle}.
   * @throws GeneralSecurityException
   */
  public static HybridDecrypt getPrimitive(KeysetHandle keysetHandle)
      throws GeneralSecurityException {
    return getPrimitive(keysetHandle, /* keyManager= */ null);
  }
  /**
   * @return a HybridDecrypt primitive from a {@code keysetHandle} and a custom {@code keyManager}.
   * @throws GeneralSecurityException
   */
  public static HybridDecrypt getPrimitive(
      KeysetHandle keysetHandle, final KeyManager<HybridDecrypt> keyManager)
      throws GeneralSecurityException {
    final PrimitiveSet<HybridDecrypt> primitives = Registry.getPrimitives(keysetHandle, keyManager);
    validate(primitives);
    return new HybridDecrypt() {
      @Override
      public byte[] decrypt(final byte[] ciphertext, final byte[] contextInfo)
          throws GeneralSecurityException {
        if (ciphertext.length > CryptoFormat.NON_RAW_PREFIX_SIZE) {
          byte[] prefix = Arrays.copyOfRange(ciphertext, 0, CryptoFormat.NON_RAW_PREFIX_SIZE);
          byte[] ciphertextNoPrefix =
              Arrays.copyOfRange(ciphertext, CryptoFormat.NON_RAW_PREFIX_SIZE, ciphertext.length);
          List<PrimitiveSet.Entry<HybridDecrypt>> entries = primitives.getPrimitive(prefix);
          for (PrimitiveSet.Entry<HybridDecrypt> entry : entries) {
            try {
              return entry.getPrimitive().decrypt(ciphertextNoPrefix, contextInfo);
            } catch (GeneralSecurityException e) {
              logger.info("ciphertext prefix matches a key, but cannot decrypt: " + e.toString());
              continue;
            }
          }
        }
        // Let's try all RAW keys.
        List<PrimitiveSet.Entry<HybridDecrypt>> entries = primitives.getRawPrimitives();
        for (PrimitiveSet.Entry<HybridDecrypt> entry : entries) {
          try {
            return entry.getPrimitive().decrypt(ciphertext, contextInfo);
          } catch (GeneralSecurityException e) {
            continue;
          }
        }
        // nothing works.
        throw new GeneralSecurityException("decryption failed");
      }
    };
  }

  // Check that all primitives in <code>pset</code> are HybridDecrypt instances.
  private static void validate(final PrimitiveSet<HybridDecrypt> pset)
      throws GeneralSecurityException {
    for (Collection<PrimitiveSet.Entry<HybridDecrypt>> entries : pset.getAll()) {
      for (PrimitiveSet.Entry<HybridDecrypt> entry : entries) {
        if (!(entry.getPrimitive() instanceof HybridDecrypt)) {
          throw new GeneralSecurityException("invalid HybridDecrypt key material");
        }
      }
    }
  }
}
