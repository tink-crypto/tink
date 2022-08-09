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

package com.google.crypto.tink.mac;

import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.PrimitiveWrapper;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.internal.MonitoringUtil;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.monitoring.MonitoringClient;
import com.google.crypto.tink.monitoring.MonitoringKeysetInfo;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.Bytes;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

/**
 * MacWrapper is the implementation of PrimitiveWrapper for the Mac primitive.
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To compute a MAC tag,
 * it uses the primary key in the keyset, and prepends to the tag a certain prefix associated with
 * the primary key. To verify a tag, the primitive uses the prefix of the tag to efficiently select
 * the right key in the set. If the keys associated with the prefix do not validate the tag, the
 * primitive tries all keys with {@link com.google.crypto.tink.proto.OutputPrefixType#RAW}.
 */
class MacWrapper implements PrimitiveWrapper<Mac, Mac> {
  private static final Logger logger = Logger.getLogger(MacWrapper.class.getName());

  private static final byte[] FORMAT_VERSION = new byte[] {0};

  private static class WrappedMac implements Mac {
    private final PrimitiveSet<Mac> primitives;
    private final MonitoringClient.Logger computeLogger;
    private final MonitoringClient.Logger verifyLogger;

    private WrappedMac(PrimitiveSet<Mac> primitives) {
      this.primitives = primitives;
      if (primitives.hasAnnotations()) {
        MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
        MonitoringKeysetInfo keysetInfo = MonitoringUtil.getMonitoringKeysetInfo(primitives);
        computeLogger = client.createLogger(keysetInfo, "mac", "compute");
        verifyLogger = client.createLogger(keysetInfo, "mac", "verify");
      } else {
        computeLogger = MonitoringUtil.DO_NOTHING_LOGGER;
        verifyLogger = MonitoringUtil.DO_NOTHING_LOGGER;
      }
    }

    @Override
    public byte[] computeMac(final byte[] data) throws GeneralSecurityException {
      byte[] data2 = data;
      if (primitives.getPrimary().getOutputPrefixType().equals(OutputPrefixType.LEGACY)) {
        data2 = com.google.crypto.tink.subtle.Bytes.concat(data, FORMAT_VERSION);
      }
      try {
        byte[] output =
            com.google.crypto.tink.subtle.Bytes.concat(
                primitives.getPrimary().getIdentifier(),
                primitives.getPrimary().getPrimitive().computeMac(data2));
        computeLogger.log(primitives.getPrimary().getKeyId(), data2.length);
        return output;
      } catch (GeneralSecurityException e) {
        computeLogger.logFailure();
        throw e;
      }
    }

    @Override
    public void verifyMac(final byte[] mac, final byte[] data) throws GeneralSecurityException {
      if (mac.length <= CryptoFormat.NON_RAW_PREFIX_SIZE) {
        // This also rejects raw MAC with size of 4 bytes or fewer. Those MACs are
        // clearly insecure, thus should be discouraged.
        verifyLogger.logFailure();
        throw new GeneralSecurityException("tag too short");
      }
      byte[] prefix = Arrays.copyOf(mac, CryptoFormat.NON_RAW_PREFIX_SIZE);
      byte[] macNoPrefix = Arrays.copyOfRange(mac, CryptoFormat.NON_RAW_PREFIX_SIZE, mac.length);
      List<PrimitiveSet.Entry<Mac>> entries = primitives.getPrimitive(prefix);
      for (PrimitiveSet.Entry<Mac> entry : entries) {
        byte[] data2 = data;
        if (entry.getOutputPrefixType().equals(OutputPrefixType.LEGACY)) {
          data2 = com.google.crypto.tink.subtle.Bytes.concat(data, FORMAT_VERSION);
        }
        try {
          entry.getPrimitive().verifyMac(macNoPrefix, data2);
          verifyLogger.log(entry.getKeyId(), data2.length);
          // If there is no exception, the MAC is valid and we can return.
          return;
        } catch (GeneralSecurityException e) {
          logger.info("tag prefix matches a key, but cannot verify: " + e);
          // Ignored as we want to continue verification with the remaining keys.
        }
      }

      // None "non-raw" key matched, so let's try the raw keys (if any exist).
      entries = primitives.getRawPrimitives();
      for (PrimitiveSet.Entry<Mac> entry : entries) {
        try {
          entry.getPrimitive().verifyMac(mac, data);
          verifyLogger.log(entry.getKeyId(), data.length);
          // If there is no exception, the MAC is valid and we can return.
          return;
        } catch (GeneralSecurityException ignored) {
          // Ignored as we want to continue verification with other raw keys.
        }
      }
      // nothing works.
      verifyLogger.logFailure();
      throw new GeneralSecurityException("invalid MAC");
    }
  }

  private void validateMacKeyPrefixes(PrimitiveSet<Mac> primitives)
      throws GeneralSecurityException {
    for (List<PrimitiveSet.Entry<Mac>> entryList : primitives.getAll()) {
      for (PrimitiveSet.Entry<Mac> entry : entryList) {
        if (entry.getKey() instanceof MacKey) {
          MacKey macKey = (MacKey) entry.getKey();
          Bytes expectedOutputPrefix = Bytes.copyFrom(entry.getIdentifier());
          if (!expectedOutputPrefix.equals(macKey.getOutputPrefix())) {
            throw new GeneralSecurityException(
                "Mac Key with parameters "
                    + macKey.getParameters()
                    + " has wrong output prefix ("
                    + macKey.getOutputPrefix()
                    + ") instead of ("
                    + expectedOutputPrefix
                    + ")");
          }
        }
      }
    }
  }

  MacWrapper() {}

  @Override
  public Mac wrap(final PrimitiveSet<Mac> primitives) throws GeneralSecurityException {
    validateMacKeyPrefixes(primitives);
    return new WrappedMac(primitives);
  }

  @Override
  public Class<Mac> getPrimitiveClass() {
    return Mac.class;
  }

  @Override
  public Class<Mac> getInputPrimitiveClass() {
    return Mac.class;
  }

 public static void register() throws GeneralSecurityException {
    Registry.registerPrimitiveWrapper(new MacWrapper());
  }
}
