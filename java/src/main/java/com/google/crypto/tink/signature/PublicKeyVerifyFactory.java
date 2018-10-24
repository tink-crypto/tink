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

package com.google.crypto.tink.signature;

import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Bytes;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

/**
 * Static methods for obtaining {@link PublicKeyVerify} instances.
 *
 * <h3>Usage</h3>
 *
 * <pre>{@code
 * KeysetHandle keysetHandle = ...;
 * PublicKeyVerify verifier = PublicKeyVerifyFactory.getPrimitive(keysetHandle);
 * verifier.verify(signature, data);
 * }</pre>
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To verify a signature,
 * the primitive uses the prefix of the signature to efficiently select the right key in the set. If
 * there is no key associated with the prefix or if the keys associated with the prefix do not work,
 * the primitive tries all keys with {@link com.google.crypto.tink.proto.OutputPrefixType#RAW}.
 *
 * @since 1.0.0
 */
public final class PublicKeyVerifyFactory {
  private static final Logger logger = Logger.getLogger(PublicKeyVerifyFactory.class.getName());

  /**
   * @return a PublicKeyVerify primitive from a {@code keysetHandle}.
   * @throws GeneralSecurityException
   */
  public static PublicKeyVerify getPrimitive(KeysetHandle keysetHandle)
      throws GeneralSecurityException {
    return getPrimitive(keysetHandle, /* keyManager= */ null);
  }

  /**
   * @return a PublicKeyVerify primitive from a {@code keysetHandle} and a custom {@code
   *     keyManager}.
   * @throws GeneralSecurityException
   */
  public static PublicKeyVerify getPrimitive(
      KeysetHandle keysetHandle, final KeyManager<PublicKeyVerify> keyManager)
      throws GeneralSecurityException {
    final PrimitiveSet<PublicKeyVerify> primitives =
        Registry.getPrimitives(keysetHandle, keyManager, PublicKeyVerify.class);
    return new PublicKeyVerify() {
      @Override
      public void verify(final byte[] signature, final byte[] data)
          throws GeneralSecurityException {
        if (signature.length <= CryptoFormat.NON_RAW_PREFIX_SIZE) {
          // This also rejects raw signatures with size of 4 bytes or fewer. We're not aware of any
          // schemes that output signatures that small.
          throw new GeneralSecurityException("signature too short");
        }
        byte[] prefix = Arrays.copyOfRange(signature, 0, CryptoFormat.NON_RAW_PREFIX_SIZE);
        byte[] sigNoPrefix =
            Arrays.copyOfRange(signature, CryptoFormat.NON_RAW_PREFIX_SIZE, signature.length);
        List<PrimitiveSet.Entry<PublicKeyVerify>> entries = primitives.getPrimitive(prefix);
        for (PrimitiveSet.Entry<PublicKeyVerify> entry : entries) {
          try {
            if (entry.getOutputPrefixType().equals(OutputPrefixType.LEGACY)) {
              final byte[] formatVersion = new byte[] {CryptoFormat.LEGACY_START_BYTE};
              final byte[] dataWithFormatVersion = Bytes.concat(data, formatVersion);
              entry.getPrimitive().verify(sigNoPrefix, dataWithFormatVersion);
            } else {
              entry.getPrimitive().verify(sigNoPrefix, data);
            }
            // If there is no exception, the signature is valid and we can return.
            return;
          } catch (GeneralSecurityException e) {
            logger.info("signature prefix matches a key, but cannot verify: " + e.toString());
            // Ignored as we want to continue verification with the remaining keys.
          }
        }

        // None "non-raw" key matched, so let's try the raw keys (if any exist).
        entries = primitives.getRawPrimitives();
        for (PrimitiveSet.Entry<PublicKeyVerify> entry : entries) {
          try {
            entry.getPrimitive().verify(signature, data);
            // If there is no exception, the signature is valid and we can return.
            return;
          } catch (GeneralSecurityException e) {
            // Ignored as we want to continue verification with raw keys.
          }
        }
        // nothing works.
        throw new GeneralSecurityException("invalid signature");
      }
    };
  }
}
