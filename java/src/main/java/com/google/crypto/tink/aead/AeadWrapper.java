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
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.PrimitiveWrapper;
import com.google.crypto.tink.subtle.Bytes;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

/**
 * AeadWrapper is the implementation of SetWrapper for the Aead primitive.
 *
 * <p>Key rotation works as follows: each ciphertext is prefixed with the keyId. When decrypting, we
 * first try all primitives whose keyId starts with the prefix of the ciphertext. If none of these
 * succeed, we try the raw primitives. If any succeeds, we return the ciphertext, otherwise we
 * simply throw a GeneralSecurityException.
 */
class AeadWrapper implements PrimitiveWrapper<Aead> {
  private static final Logger logger = Logger.getLogger(AeadWrapper.class.getName());

  private static class WrappedAead implements Aead {
    private final PrimitiveSet<Aead> pSet;
    private WrappedAead(PrimitiveSet<Aead> pSet) {
      this.pSet = pSet;
    }

    @Override
    public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
        throws GeneralSecurityException {
      return Bytes.concat(
          pSet.getPrimary().getIdentifier(),
          pSet.getPrimary().getPrimitive().encrypt(plaintext, associatedData));
    }

    @Override
    public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
        throws GeneralSecurityException {
      if (ciphertext.length > CryptoFormat.NON_RAW_PREFIX_SIZE) {
        byte[] prefix = Arrays.copyOfRange(ciphertext, 0, CryptoFormat.NON_RAW_PREFIX_SIZE);
        byte[] ciphertextNoPrefix =
            Arrays.copyOfRange(ciphertext, CryptoFormat.NON_RAW_PREFIX_SIZE, ciphertext.length);
        List<PrimitiveSet.Entry<Aead>> entries = pSet.getPrimitive(prefix);
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
      List<PrimitiveSet.Entry<Aead>> entries = pSet.getRawPrimitives();
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
  }

  @Override
  public Aead wrap(final PrimitiveSet<Aead> pset) throws GeneralSecurityException {
    return new WrappedAead(pset);
  }

  @Override
  public Class<Aead> getPrimitiveClass() {
    return Aead.class;
  }
}
