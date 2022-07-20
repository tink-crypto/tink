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
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.internal.MonitoringUtil;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.monitoring.MonitoringClient;
import com.google.crypto.tink.monitoring.MonitoringKeysetInfo;
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
public class AeadWrapper implements PrimitiveWrapper<Aead, Aead> {
  private static final Logger logger = Logger.getLogger(AeadWrapper.class.getName());

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
        byte[] output =
            Bytes.concat(
                pSet.getPrimary().getIdentifier(),
                pSet.getPrimary().getPrimitive().encrypt(plaintext, associatedData));
        encLogger.log(pSet.getPrimary().getKeyId(), plaintext.length);
        return output;
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
        byte[] ciphertextNoPrefix =
            Arrays.copyOfRange(ciphertext, CryptoFormat.NON_RAW_PREFIX_SIZE, ciphertext.length);
        List<PrimitiveSet.Entry<Aead>> entries = pSet.getPrimitive(prefix);
        for (PrimitiveSet.Entry<Aead> entry : entries) {
          try {
            byte[] result = entry.getPrimitive().decrypt(ciphertextNoPrefix, associatedData);
            decLogger.log(entry.getKeyId(), ciphertextNoPrefix.length);
            return result;
          } catch (GeneralSecurityException e) {
            logger.info("ciphertext prefix matches a key, but cannot decrypt: " + e);
            continue;
          }
        }
      }

      // Let's try all RAW keys.
      List<PrimitiveSet.Entry<Aead>> entries = pSet.getRawPrimitives();
      for (PrimitiveSet.Entry<Aead> entry : entries) {
        try {
          byte[] result = entry.getPrimitive().decrypt(ciphertext, associatedData);
          decLogger.log(entry.getKeyId(), ciphertext.length);
          return result;
        } catch (GeneralSecurityException e) {
          continue;
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
    Registry.registerPrimitiveWrapper(new AeadWrapper());
  }
}
