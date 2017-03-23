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

package com.google.cloud.crypto.tink.signature;

import com.google.cloud.crypto.tink.CryptoFormat;
import com.google.cloud.crypto.tink.KeyManager;
import com.google.cloud.crypto.tink.KeysetHandle;
import com.google.cloud.crypto.tink.PrimitiveSet;
import com.google.cloud.crypto.tink.PublicKeyVerify;
import com.google.cloud.crypto.tink.Registry;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

/**
 * PublicKeyVerifyFactory allows obtaining a {@code PublicKeyVerify} primitive from a
 * {@code KeysetHandle}.
 *
 * PublicKeyVerifyFactory gets primitives from the {@code Registry}. The factory allows initalizing
 * the {@code Registry} with native key types and their managers that Tink supports out of the box.
 * These key types are divided in two groups:
 *   - standard: secure and safe to use in new code. Over time, with new developments in
 *               cryptanalysis and computing power, some standard key types might become legacy.
 *   - legacy: deprecated and insecure or obsolete, should not be used in new code. Existing users
 *             should upgrade to one of the standard key types.
 * This divison allows for gradual retiring insecure or obsolete key types.
 *
 * For example, here is how one can obtain and use a PublicKeyVerify primitive:
 * <pre>   {@code
 *   KeysetHandle keysetHandle = ...;
 *   PublicKeyVerifyFactory.registerStandardKeyTypes();
 *   PublicKeyVerify verifier = PublicKeyVerifyFactory.getPrimitive(keysetHandle);
 *   verifier.verify(signature, data);
 *  }</pre>
 * The returned primitive works with a keyset (rather than a single key). To verify a signature,
 * the primitive uses the prefix of the signature to efficiently select the right key in the set.
 * If there is no key associated with the prefix or if the keys associated with the prefix do not
 * work, the primitive tries all keys with {@code OutputPrefixType.RAW}.
 */
public final class PublicKeyVerifyFactory {
  private static final Logger logger =
      Logger.getLogger(PublicKeyVerifyFactory.class.getName());

  /**
   * Registers standard PublicKeyVerify key types and their managers with the {@code Registry}.
   * @throws GeneralSecurityException
   */
  public static void registerStandardKeyTypes() throws GeneralSecurityException {
    Registry.INSTANCE.registerKeyManager(
        "type.googleapis.com/google.cloud.crypto.tink.EcdsaPublicKey",
        new EcdsaVerifyKeyManager());
  }

  /**
   * Registers legacy PublicKeyVerify key types and their managers with the {@code Registry}.
   * @throws GeneralSecurityException
   */
  public static void registerLegacyKeyTypes() throws GeneralSecurityException {
    ;
  }

  /**
   * @return a PublicKeyVerify primitive from a {@code keysetHandle}.
   * @throws GeneralSecurityException
   */
  public static PublicKeyVerify getPrimitive(KeysetHandle keysetHandle)
      throws GeneralSecurityException {
        return getPrimitive(keysetHandle, null /* keyManager */);
      }

  /**
   * @return a PublicKeyVerify primitive from a {@code keysetHandle} and a custom
   * {@code keyManager}.
   * @throws GeneralSecurityException
   */
  public static <K extends MessageLite, F extends MessageLite> PublicKeyVerify getPrimitive(
      KeysetHandle keysetHandle, final KeyManager<PublicKeyVerify, K, F> keyManager)
      throws GeneralSecurityException {
    PrimitiveSet<PublicKeyVerify> primitives =
        Registry.INSTANCE.getPrimitives(keysetHandle, keyManager);
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
        byte[] sigNoPrefix = Arrays.copyOfRange(signature, CryptoFormat.NON_RAW_PREFIX_SIZE,
            signature.length);
        List<PrimitiveSet<PublicKeyVerify>.Entry<PublicKeyVerify>> entries =
            primitives.getPrimitive(prefix);
        for (PrimitiveSet<PublicKeyVerify>.Entry<PublicKeyVerify> entry : entries) {
          try {
            entry.getPrimitive().verify(sigNoPrefix, data);
            // If there is no exception, the signature is valid and we can return.
            return;
          } catch (GeneralSecurityException e) {
            logger.info("signature prefix matches a key, but cannot verify: " + e.toString());
            // Ignored as we want to continue verification with the remaining keys.
          }
        }

        // None "non-raw" key matched, so let's try the raw keys (if any exist).
        entries = primitives.getRawPrimitives();
        for (PrimitiveSet<PublicKeyVerify>.Entry<PublicKeyVerify> entry : entries) {
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
