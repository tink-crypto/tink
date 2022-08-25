// Copyright 2020 Google LLC
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
package com.google.crypto.tink.prf;

import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.PrimitiveWrapper;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.internal.MonitoringUtil;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.monitoring.MonitoringClient;
import com.google.crypto.tink.monitoring.MonitoringKeysetInfo;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * PrfSetWrapper is the implementation of PrimitiveWrapper for the PrfSet primitive.
 *
 * <p>The returned primitive has instances of {@code Prf} for each key in the KeySet. The individual
 * Prf instances can then be used to compute psuedo-random sequences from the underlying key.
 */
@Immutable
public class PrfSetWrapper implements PrimitiveWrapper<Prf, PrfSet> {
  private static class WrappedPrfSet extends PrfSet {
    // This map is constructed using Collections.unmodifiableMap
    @SuppressWarnings("Immutable")
    private final Map<Integer, Prf> keyIdToPrfMap;

    private final int primaryKeyId;

    @Immutable
    private static class PrfWithMonitoring implements Prf {
      private final Prf prf;
      private final int keyId;

      @SuppressWarnings("Immutable")
      private final MonitoringClient.Logger logger;

      @Override
      public byte[] compute(byte[] input, int outputLength) throws GeneralSecurityException {
        try {
          byte[] output = prf.compute(input, outputLength);
          logger.log(keyId, input.length);
          return output;
        } catch (GeneralSecurityException e) {
          logger.logFailure();
          throw e;
        }
      }

      public PrfWithMonitoring(Prf prf, int keyId, MonitoringClient.Logger logger) {
        this.prf = prf;
        this.keyId = keyId;
        this.logger = logger;
      }
    }

    private WrappedPrfSet(PrimitiveSet<Prf> primitives) throws GeneralSecurityException {
      if (primitives.getRawPrimitives().isEmpty()) {
        throw new GeneralSecurityException("No primitives provided.");
      }
      if (primitives.getPrimary() == null) {
        throw new GeneralSecurityException("Primary key not set.");
      }
      MonitoringClient.Logger logger;
      if (primitives.hasAnnotations()) {
        MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
        MonitoringKeysetInfo keysetInfo = MonitoringUtil.getMonitoringKeysetInfo(primitives);
        logger = client.createLogger(keysetInfo, "prf", "compute");
      } else {
        logger = MonitoringUtil.DO_NOTHING_LOGGER;
      }

      primaryKeyId = primitives.getPrimary().getKeyId();
      List<PrimitiveSet.Entry<Prf>> entries = primitives.getRawPrimitives();
      Map<Integer, Prf> mutablePrfMap = new HashMap<>();
      for (PrimitiveSet.Entry<Prf> entry : entries) {
        if (!entry.getOutputPrefixType().equals(OutputPrefixType.RAW)) {
          throw new GeneralSecurityException(
              "Key " + entry.getKeyId() + " has non raw prefix type");
        }
        // Likewise, the key IDs of the PrfSet passed
        mutablePrfMap.put(
            entry.getKeyId(),
            new PrfWithMonitoring(entry.getPrimitive(), entry.getKeyId(), logger));
      }
      keyIdToPrfMap = Collections.unmodifiableMap(mutablePrfMap);
    }

    @Override
    public int getPrimaryId() {
      return primaryKeyId;
    }

    @Override
    public Map<Integer, Prf> getPrfs() throws GeneralSecurityException {
      return keyIdToPrfMap;
    }
  }

  @Override
  public PrfSet wrap(PrimitiveSet<Prf> set) throws GeneralSecurityException {
    return new WrappedPrfSet(set);
  }

  @Override
  public Class<PrfSet> getPrimitiveClass() {
    return PrfSet.class;
  }

  @Override
  public Class<Prf> getInputPrimitiveClass() {
    return Prf.class;
  }

  public static void register() throws GeneralSecurityException {
    Registry.registerPrimitiveWrapper(new PrfSetWrapper());
  }
}
