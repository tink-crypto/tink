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

import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.PrimitiveWrapper;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.internal.MonitoringUtil;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.monitoring.MonitoringClient;
import com.google.crypto.tink.monitoring.MonitoringKeysetInfo;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Bytes;
import java.security.GeneralSecurityException;

/**
 * The implementation of {@code PrimitiveWrapper<PublicKeySign>}.
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To sign a message, it
 * uses the primary key in the keyset, and prepends to the signature a certain prefix associated
 * with the primary key.
 */
public class PublicKeySignWrapper implements PrimitiveWrapper<PublicKeySign, PublicKeySign> {

  private static final byte[] FORMAT_VERSION = new byte[] {0};

  private static class WrappedPublicKeySign implements PublicKeySign {
    private final PrimitiveSet<PublicKeySign> primitives;

    private final MonitoringClient.Logger logger;

    public WrappedPublicKeySign(final PrimitiveSet<PublicKeySign> primitives) {
      this.primitives = primitives;
      if (primitives.hasAnnotations()) {
        MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
        MonitoringKeysetInfo keysetInfo = MonitoringUtil.getMonitoringKeysetInfo(primitives);
        this.logger = client.createLogger(keysetInfo, "public_key_sign", "sign");
      } else {
        this.logger = MonitoringUtil.DO_NOTHING_LOGGER;
      }
    }

    @Override
    public byte[] sign(final byte[] data) throws GeneralSecurityException {
      byte[] data2 = data;
      if (primitives.getPrimary().getOutputPrefixType().equals(OutputPrefixType.LEGACY)) {
        data2 = Bytes.concat(data, FORMAT_VERSION);
      }
      try {
        byte[] output =
            Bytes.concat(
                primitives.getPrimary().getIdentifier(),
                primitives.getPrimary().getPrimitive().sign(data2));
        logger.log(primitives.getPrimary().getKeyId(), data2.length);
        return output;
      } catch (GeneralSecurityException e) {
        logger.logFailure();
        throw e;
      }
    }
  }

  PublicKeySignWrapper() {}

  @Override
  public PublicKeySign wrap(final PrimitiveSet<PublicKeySign> primitives) {
    return new WrappedPublicKeySign(primitives);
  }

  @Override
  public Class<PublicKeySign> getPrimitiveClass() {
    return PublicKeySign.class;
  }

  @Override
  public Class<PublicKeySign> getInputPrimitiveClass() {
    return PublicKeySign.class;
  }

  /**
   * Register the wrapper within the registry.
   *
   * <p>This is required for calls to {@link Keyset.getPrimitive} with a {@link PublicKeySign}
   * argument.
   */
  public static void register() throws GeneralSecurityException {
    Registry.registerPrimitiveWrapper(new PublicKeySignWrapper());
  }
}
