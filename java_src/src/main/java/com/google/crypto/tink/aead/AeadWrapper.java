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
import com.google.crypto.tink.aead.internal.LegacyFullAead;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MonitoringUtil;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.monitoring.MonitoringClient;
import com.google.crypto.tink.monitoring.MonitoringKeysetInfo;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;

/**
 * AeadWrapper is the implementation of SetWrapper for the Aead primitive.
 *
 * <p>Key rotation works as follows: each ciphertext is prefixed with the keyId. When decrypting, we
 * first try all primitives whose keyId starts with the prefix of the ciphertext. If none of these
 * succeed, we try the raw primitives. If any succeeds, we return the ciphertext, otherwise we
 * simply throw a GeneralSecurityException.
 */
public class AeadWrapper implements PrimitiveWrapper<Aead, Aead> {

  private static final AeadWrapper WRAPPER = new AeadWrapper();
  private static final PrimitiveConstructor<LegacyProtoKey, Aead>
      LEGACY_FULL_AEAD_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(LegacyFullAead::create, LegacyProtoKey.class, Aead.class);

  private static class WrappedAead implements Aead {
    private final PrimitiveSet<Aead> pSet;
    private final MonitoringClient.Logger encLogger;
    private final MonitoringClient.Logger decLogger;

    private WrappedAead(PrimitiveSet<Aead> pSet) {
      this.pSet = pSet;
      if (pSet.hasAnnotations()) {
        MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
        MonitoringKeysetInfo keysetInfo = MonitoringUtil.getMonitoringKeysetInfo(pSet);
        this.encLogger = client.createLogger(keysetInfo, "aead", "encrypt");
        this.decLogger = client.createLogger(keysetInfo, "aead", "decrypt");
      } else {
        this.encLogger = MonitoringUtil.DO_NOTHING_LOGGER;
        this.decLogger = MonitoringUtil.DO_NOTHING_LOGGER;
      }
    }

    @Override
    public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
        throws GeneralSecurityException {
      try {
        byte[] result = pSet.getPrimary().getFullPrimitive().encrypt(plaintext, associatedData);
        encLogger.log(pSet.getPrimary().getKeyId(), plaintext.length);
        return result;
      } catch (GeneralSecurityException e) {
        encLogger.logFailure();
        throw e;
      }
    }

    @Override
    public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
        throws GeneralSecurityException {
      if (ciphertext.length > CryptoFormat.NON_RAW_PREFIX_SIZE) {
        byte[] prefix = Arrays.copyOf(ciphertext, CryptoFormat.NON_RAW_PREFIX_SIZE);
        List<PrimitiveSet.Entry<Aead>> entries = pSet.getPrimitive(prefix);
        for (PrimitiveSet.Entry<Aead> entry : entries) {
          try {
            byte[] result = entry.getFullPrimitive().decrypt(ciphertext, associatedData);
            decLogger.log(entry.getKeyId(), ciphertext.length);
            return result;
          } catch (GeneralSecurityException ignored) {
            // ignore and continue trying
          }
        }
      }

      // Let's try all RAW keys.
      List<PrimitiveSet.Entry<Aead>> entries = pSet.getRawPrimitives();
      for (PrimitiveSet.Entry<Aead> entry : entries) {
        try {
          byte[] result = entry.getFullPrimitive().decrypt(ciphertext, associatedData);
          decLogger.log(entry.getKeyId(), ciphertext.length);
          return result;
        } catch (GeneralSecurityException ignored) {
          // ignore and continue trying
        }
      }
      decLogger.logFailure();
      // nothing works.
      throw new GeneralSecurityException("decryption failed");
    }
  }

  AeadWrapper() {}

  @Override
  public Aead wrap(final PrimitiveSet<Aead> pset) throws GeneralSecurityException {
    return new WrappedAead(pset);
  }

  @Override
  public Class<Aead> getPrimitiveClass() {
    return Aead.class;
  }

  @Override
  public Class<Aead> getInputPrimitiveClass() {
    return Aead.class;
  }

  public static void register() throws GeneralSecurityException {
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(WRAPPER);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(LEGACY_FULL_AEAD_PRIMITIVE_CONSTRUCTOR);
  }
}
