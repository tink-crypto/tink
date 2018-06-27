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

import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.subtle.Bytes;
import java.security.GeneralSecurityException;
import java.util.Collection;
import java.util.logging.Logger;

/**
 * Static methods for obtaining {@link HybridEncrypt} instances.
 *
 * <h3>Usage</h3>
 *
 * <pre>{@code
 * KeysetHandle keysetHandle = ...;
 * HybridEncrypt hybridEncrypt = HybridEncryptFactory.getPrimitive(keysetHandle);
 * byte[] plaintext = ...;
 * byte[] contextInfo = ...;
 * byte[] ciphertext = hybridEncrypt.encrypt(plaintext, contextInfo);
 * }</pre>
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To encrypt a plaintext,
 * it uses the primary key in the keyset, and prepends to the ciphertext a certain prefix associated
 * with the primary key.
 *
 * @since 1.0.0
 */
public final class HybridEncryptFactory {
  private static final Logger logger = Logger.getLogger(HybridEncryptFactory.class.getName());

  /**
   * @return a HybridEncrypt primitive from a {@code keysetHandle}.
   * @throws GeneralSecurityException
   */
  public static HybridEncrypt getPrimitive(KeysetHandle keysetHandle)
      throws GeneralSecurityException {
    return getPrimitive(keysetHandle, /* keyManager= */ null);
  }

  /**
   * @return a HybridEncrypt primitive from a {@code keysetHandle} and a custom {@code keyManager}.
   * @throws GeneralSecurityException
   */
  public static HybridEncrypt getPrimitive(
      KeysetHandle keysetHandle, final KeyManager<HybridEncrypt> keyManager)
      throws GeneralSecurityException {
    final PrimitiveSet<HybridEncrypt> primitives = Registry.getPrimitives(keysetHandle, keyManager);
    validate(primitives);
    return new HybridEncrypt() {
      @Override
      public byte[] encrypt(final byte[] plaintext, final byte[] contextInfo)
          throws GeneralSecurityException {
        return Bytes.concat(
            primitives.getPrimary().getIdentifier(),
            primitives.getPrimary().getPrimitive().encrypt(plaintext, contextInfo));
      }
    };
  }

  // Check that all primitives in <code>pset</code> are HybridEncrypt instances.
  private static void validate(final PrimitiveSet<HybridEncrypt> pset)
      throws GeneralSecurityException {
    for (Collection<PrimitiveSet.Entry<HybridEncrypt>> entries : pset.getAll()) {
      for (PrimitiveSet.Entry<HybridEncrypt> entry : entries) {
        if (!(entry.getPrimitive() instanceof HybridEncrypt)) {
          throw new GeneralSecurityException("invalid HybridEncrypt key material");
        }
      }
    }
  }
}
