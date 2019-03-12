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

package com.google.crypto.tink.daead;

import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.PrimitiveWrapper;
import com.google.crypto.tink.subtle.Bytes;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

/**
 * The implementation of {@code PrimitiveWrapper<DeterministicAead>}.
 *
 * <p>The created primitive works with a keyset (rather than a single key). To encrypt a plaintext,
 * it uses the primary key in the keyset, and prepends to the ciphertext a certain prefix associated
 * with the primary key. To decrypt, the primitive uses the prefix of the ciphertext to efficiently
 * select the right key in the set. If the keys associated with the prefix do not work, the
 * primitive tries all keys with {@link com.google.crypto.tink.proto.OutputPrefixType#RAW}.
 */
class DeterministicAeadWrapper implements PrimitiveWrapper<DeterministicAead> {
  private static final Logger logger = Logger.getLogger(DeterministicAeadWrapper.class.getName());

  private static class WrappedDeterministicAead implements DeterministicAead {
    private PrimitiveSet<DeterministicAead> primitives;

    public WrappedDeterministicAead(PrimitiveSet<DeterministicAead> primitives) {
      this.primitives = primitives;
    }

    @Override
    public byte[] encryptDeterministically(final byte[] plaintext, final byte[] associatedData)
        throws GeneralSecurityException {
      return Bytes.concat(
          primitives.getPrimary().getIdentifier(),
          primitives
              .getPrimary()
              .getPrimitive()
              .encryptDeterministically(plaintext, associatedData));
    }

    @Override
    public byte[] decryptDeterministically(final byte[] ciphertext, final byte[] associatedData)
        throws GeneralSecurityException {
      if (ciphertext.length > CryptoFormat.NON_RAW_PREFIX_SIZE) {
        byte[] prefix = Arrays.copyOfRange(ciphertext, 0, CryptoFormat.NON_RAW_PREFIX_SIZE);
        byte[] ciphertextNoPrefix =
            Arrays.copyOfRange(ciphertext, CryptoFormat.NON_RAW_PREFIX_SIZE, ciphertext.length);
        List<PrimitiveSet.Entry<DeterministicAead>> entries = primitives.getPrimitive(prefix);
        for (PrimitiveSet.Entry<DeterministicAead> entry : entries) {
          try {
            return entry
                .getPrimitive()
                .decryptDeterministically(ciphertextNoPrefix, associatedData);
          } catch (GeneralSecurityException e) {
            logger.info("ciphertext prefix matches a key, but cannot decrypt: " + e.toString());
            continue;
          }
        }
      }

      // Let's try all RAW keys.
      List<PrimitiveSet.Entry<DeterministicAead>> entries = primitives.getRawPrimitives();
      for (PrimitiveSet.Entry<DeterministicAead> entry : entries) {
        try {
          return entry.getPrimitive().decryptDeterministically(ciphertext, associatedData);
        } catch (GeneralSecurityException e) {
          continue;
        }
      }
      // nothing works.
      throw new GeneralSecurityException("decryption failed");
    }
  }

  @Override
  public DeterministicAead wrap(final PrimitiveSet<DeterministicAead> primitives) {
    return new WrappedDeterministicAead(primitives);
  }

  @Override
  public Class<DeterministicAead> getPrimitiveClass() {
    return DeterministicAead.class;
  }
}
