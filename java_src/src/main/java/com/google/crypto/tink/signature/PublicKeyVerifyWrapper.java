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
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.PrimitiveWrapper;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.internal.MonitoringUtil;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.monitoring.MonitoringClient;
import com.google.crypto.tink.monitoring.MonitoringKeysetInfo;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Bytes;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

/**
 * The implementation of {@code PrimitiveWrapper<DeterministicAead>}.
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To verify a signature,
 * the primitive uses the prefix of the signature to efficiently select the right key in the set. If
 * there is no key associated with the prefix or if the keys associated with the prefix do not work,
 * the primitive tries all keys with {@link com.google.crypto.tink.proto.OutputPrefixType#RAW}.
 *
 * @since 1.0.0
 */
class PublicKeyVerifyWrapper implements PrimitiveWrapper<PublicKeyVerify, PublicKeyVerify> {
  private static final Logger logger = Logger.getLogger(PublicKeyVerifyWrapper.class.getName());

  private static final byte[] FORMAT_VERSION = new byte[] {0};

  private static class WrappedPublicKeyVerify implements PublicKeyVerify {
    private final PrimitiveSet<PublicKeyVerify> primitives;

    private final MonitoringClient.Logger monitoringLogger;

    public WrappedPublicKeyVerify(PrimitiveSet<PublicKeyVerify> primitives) {
      this.primitives = primitives;
      if (primitives.hasAnnotations()) {
        MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
        MonitoringKeysetInfo keysetInfo = MonitoringUtil.getMonitoringKeysetInfo(primitives);
        this.monitoringLogger = client.createLogger(keysetInfo, "public_key_verify", "verify");
      } else {
        this.monitoringLogger = MonitoringUtil.DO_NOTHING_LOGGER;
      }
    }

    @Override
    public void verify(final byte[] signature, final byte[] data) throws GeneralSecurityException {
      if (signature.length <= CryptoFormat.NON_RAW_PREFIX_SIZE) {
        // This also rejects raw signatures with size of 4 bytes or fewer. We're not aware of any
        // schemes that output signatures that small.
        monitoringLogger.logFailure();
        throw new GeneralSecurityException("signature too short");
      }
      byte[] prefix = Arrays.copyOf(signature, CryptoFormat.NON_RAW_PREFIX_SIZE);
      byte[] sigNoPrefix =
          Arrays.copyOfRange(signature, CryptoFormat.NON_RAW_PREFIX_SIZE, signature.length);
      List<PrimitiveSet.Entry<PublicKeyVerify>> entries = primitives.getPrimitive(prefix);
      for (PrimitiveSet.Entry<PublicKeyVerify> entry : entries) {
        byte[] data2 = data;
        if (entry.getOutputPrefixType().equals(OutputPrefixType.LEGACY)) {
          data2 = Bytes.concat(data2, FORMAT_VERSION);
        }
        try {
          entry.getPrimitive().verify(sigNoPrefix, data2);
          monitoringLogger.log(entry.getKeyId(), data2.length);
          // If there is no exception, the signature is valid and we can return.
          return;
        } catch (GeneralSecurityException e) {
          logger.info("signature prefix matches a key, but cannot verify: " + e);
          // Ignored as we want to continue verification with the remaining keys.
        }
      }

      // None "non-raw" key matched, so let's try the raw keys (if any exist).
      entries = primitives.getRawPrimitives();
      for (PrimitiveSet.Entry<PublicKeyVerify> entry : entries) {
        try {
          entry.getPrimitive().verify(signature, data);
          monitoringLogger.log(entry.getKeyId(), data.length);
          // If there is no exception, the signature is valid and we can return.
          return;
        } catch (GeneralSecurityException e) {
          // Ignored as we want to continue verification with raw keys.
        }
      }
      // nothing works.
      monitoringLogger.logFailure();
      throw new GeneralSecurityException("invalid signature");
    }
  }

  @Override
  public PublicKeyVerify wrap(final PrimitiveSet<PublicKeyVerify> primitives) {
    return new WrappedPublicKeyVerify(primitives);
  }

  @Override
  public Class<PublicKeyVerify> getPrimitiveClass() {
    return PublicKeyVerify.class;
  }

  @Override
  public Class<PublicKeyVerify> getInputPrimitiveClass() {
    return PublicKeyVerify.class;
  }

  /**
   * Register the wrapper within the registry.
   *
   * <p>This is required for calls to {@link Keyset.getPrimitive} with a {@link PublicKeyVerify}
   * argument.
   */
  public static void register() throws GeneralSecurityException {
    Registry.registerPrimitiveWrapper(new PublicKeyVerifyWrapper());
  }
}
