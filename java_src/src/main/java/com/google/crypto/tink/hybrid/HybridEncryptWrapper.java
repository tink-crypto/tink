// Copyright 2017 Google LLC
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
import com.google.crypto.tink.PrimitiveWrapper;
import com.google.crypto.tink.hybrid.internal.LegacyFullHybridEncrypt;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MonitoringUtil;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveSet;
import com.google.crypto.tink.monitoring.MonitoringClient;
import com.google.crypto.tink.monitoring.MonitoringKeysetInfo;
import java.security.GeneralSecurityException;

/**
 * The implementation of {@code PrimitiveWrapper<HybridEncrypt>}.
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To encrypt a plaintext,
 * it uses the primary key in the keyset, and prepends to the ciphertext a certain prefix associated
 * with the primary key.
 */
public class HybridEncryptWrapper implements PrimitiveWrapper<HybridEncrypt, HybridEncrypt> {

  private static final HybridEncryptWrapper WRAPPER = new HybridEncryptWrapper();
  private static final PrimitiveConstructor<LegacyProtoKey, HybridEncrypt>
      LEGACY_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              LegacyFullHybridEncrypt::create, LegacyProtoKey.class, HybridEncrypt.class);

  private static class WrappedHybridEncrypt implements HybridEncrypt {
    final PrimitiveSet<HybridEncrypt> primitives;

    private final MonitoringClient.Logger encLogger;

    public WrappedHybridEncrypt(final PrimitiveSet<HybridEncrypt> primitives) {
      this.primitives = primitives;
      if (primitives.hasAnnotations()) {
        MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
        MonitoringKeysetInfo keysetInfo = MonitoringUtil.getMonitoringKeysetInfo(primitives);
        this.encLogger = client.createLogger(keysetInfo, "hybrid_encrypt", "encrypt");
      } else {
        this.encLogger = MonitoringUtil.DO_NOTHING_LOGGER;
      }
    }

    @Override
    public byte[] encrypt(final byte[] plaintext, final byte[] contextInfo)
        throws GeneralSecurityException {
      if (primitives.getPrimary() == null) {
        encLogger.logFailure();
        throw new GeneralSecurityException("keyset without primary key");
      }
      try {
        byte[] output = primitives.getPrimary().getFullPrimitive().encrypt(plaintext, contextInfo);
        encLogger.log(primitives.getPrimary().getKeyId(), plaintext.length);
        return output;
      } catch (GeneralSecurityException e) {
        encLogger.logFailure();
        throw e;
      }
    }
  }

  HybridEncryptWrapper() {}

  @Override
  public HybridEncrypt wrap(final PrimitiveSet<HybridEncrypt> primitives) {
    return new WrappedHybridEncrypt(primitives);
  }

  @Override
  public Class<HybridEncrypt> getPrimitiveClass() {
    return HybridEncrypt.class;
  }

  @Override
  public Class<HybridEncrypt> getInputPrimitiveClass() {
    return HybridEncrypt.class;
  }

  /**
   * Register the wrapper within the registry.
   *
   * <p>This is required for calls to {@link Keyset.getPrimitive} with a {@link HybridEncrypt}
   * argument.
   */
  public static void register() throws GeneralSecurityException {
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(WRAPPER);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(LEGACY_PRIMITIVE_CONSTRUCTOR);
  }

  /**
   * registerToInternalPrimitiveRegistry is a non-public method (it takes an argument of an
   * internal-only type) registering an instance of {@code HybridEncryptWrapper} to the provided
   * {@code PrimitiveRegistry.Builder}.
   */
  public static void registerToInternalPrimitiveRegistry(
      PrimitiveRegistry.Builder primitiveRegistryBuilder) throws GeneralSecurityException {
    primitiveRegistryBuilder.registerPrimitiveWrapper(WRAPPER);
  }
}
