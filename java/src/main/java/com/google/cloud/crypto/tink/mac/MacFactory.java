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

package com.google.cloud.crypto.tink.mac;

import com.google.cloud.crypto.tink.CryptoFormat;
import com.google.cloud.crypto.tink.KeyManager;
import com.google.cloud.crypto.tink.KeysetHandle;
import com.google.cloud.crypto.tink.Mac;
import com.google.cloud.crypto.tink.PrimitiveSet;
import com.google.cloud.crypto.tink.Registry;
import com.google.cloud.crypto.tink.subtle.SubtleUtil;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

/**
 * MacFactory allows obtaining a primitive from a {@code KeysetHandle}.
 *
 * MacFactory gets primitives from the {@code Registry}. The factory allows initalizing the
 * {@code Registry} with native key types and their managers that Tink supports out of the box.
 * These key types are divided in two groups:
 *   - standard: secure and safe to use in new code. Over time, with new developments in
 *               cryptanalysis and computing power, some standard key types might become legacy.
 *   - legacy: deprecated and insecure or obsolete, should not be used in new code. Existing users
 *             should upgrade to one of the standard key types.
 * This divison allows for gradual retiring insecure or obsolete key types.
 *
 * For example, here is how one can obtain and use a Mac primitive:
 * <pre>   {@code
 *   KeysetHandle keysetHandle = ...;
 *   MacFactory.registerStandardKeyTypes();
 *   Mac mac = MacFactory.getPrimitive(keysetHandle);
 *   byte[] data = ...;
 *   byte[] tag = mac.computeMac(data);
 *  }</pre>
 * The returned primitive works with a keyset (rather than a single key). To compute a MAC tag, it
 * uses the primary key in the keyset, and prepends to the tag a certain prefix associated with the
 * primary key. To verify a tag, the primitive uses the prefix of the tag to efficiently select the
 * right key in the set. If the keys associated with the prefix do not validate the tag, the
 * primitive tries all keys with {@code OutputPrefixType.RAW}.
 */
public final class MacFactory {
  private static final Logger logger =
      Logger.getLogger(MacFactory.class.getName());

  /**
   * Registers standard Mac key types and their managers with the {@code Registry}.
   * @throws GeneralSecurityException
   */
  public static void registerStandardKeyTypes() throws GeneralSecurityException {
      Registry.INSTANCE.registerKeyManager("type.googleapis.com/google.cloud.crypto.tink.HmacKey",
          new HmacKeyManager());
  }

  /**
   * Registers legacy Mac key types and their managers with the {@code Registry}.
   * @throws GeneralSecurityException
   */
  public static void registerLegacyKeyTypes() throws GeneralSecurityException {
    ;
  }

  /**
   * @return a Mac primitive from a {@code keysetHandle}.
   * @throws GeneralSecurityException
   */
  public static Mac getPrimitive(KeysetHandle keysetHandle)
      throws GeneralSecurityException {
    return getPrimitive(keysetHandle, null /* keyManager */);
  }

  /**
   * @return a Mac primitive from a {@code keysetHandle} and a custom {@code keyManager}.
   * @throws GeneralSecurityException
   */
  public static <K extends MessageLite, F extends MessageLite> Mac getPrimitive(
      KeysetHandle keysetHandle, final KeyManager<Mac, K, F> keyManager)
      throws GeneralSecurityException {
    PrimitiveSet<Mac> primitives =
        Registry.INSTANCE.getPrimitives(keysetHandle, keyManager);
    return new Mac() {
      @Override
      public byte[] computeMac(final byte[] data) throws GeneralSecurityException {
        return SubtleUtil.concat(
            primitives.getPrimary().getIdentifier(),
            primitives.getPrimary().getPrimitive().computeMac(data));
      }

      @Override
      public void verifyMac(final byte[] mac, final byte[] data) throws GeneralSecurityException {
        if (mac.length <= CryptoFormat.NON_RAW_PREFIX_SIZE) {
          // This also rejects raw MAC with size of 4 bytes or fewer. Those MACs are
          // clearly insecure, thus should be discouraged.
          throw new GeneralSecurityException("tag too short");
        }
        byte[] prefix = Arrays.copyOfRange(mac, 0, CryptoFormat.NON_RAW_PREFIX_SIZE);
        byte[] macNoPrefix = Arrays.copyOfRange(mac, CryptoFormat.NON_RAW_PREFIX_SIZE,
              mac.length);
        List<PrimitiveSet<Mac>.Entry<Mac>> entries = primitives.getPrimitive(prefix);
        for (PrimitiveSet<Mac>.Entry<Mac> entry : entries) {
            try {
              entry.getPrimitive().verifyMac(macNoPrefix, data);
              // If there is no exception, the MAC is valid and we can return.
              return;
            } catch (GeneralSecurityException e) {
              logger.info("tag prefix matches a key, but cannot verify: " + e.toString());
              // Ignored as we want to continue verification with the remaining keys.
            }
        }

        // None "non-raw" key matched, so let's try the raw keys (if any exist).
        entries = primitives.getRawPrimitives();
        for (PrimitiveSet<Mac>.Entry<Mac> entry : entries) {
          try {
            entry.getPrimitive().verifyMac(mac, data);
            // If there is no exception, the MAC is valid and we can return.
            return;
          } catch (GeneralSecurityException ignored) {
            // Ignored as we want to continue verification with other raw keys.
          }
        }
        // nothing works.
        throw new GeneralSecurityException("invalid MAC");
      }
    };
  }
}
