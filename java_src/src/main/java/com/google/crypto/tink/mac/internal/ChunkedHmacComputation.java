// Copyright 2022 Google Inc.
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

package com.google.crypto.tink.mac.internal;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.mac.ChunkedMacComputation;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.HmacParameters.Variant;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.EngineFactory;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * An implementation of streaming HMAC computation. Not thread-safe, thread safety must be ensured
 * by the caller if objects of this class are accessed concurrently.
 */
@AccessesPartialKey
final class ChunkedHmacComputation implements ChunkedMacComputation {
  private static final byte[] FORMAT_VERSION = new byte[] {0};

  private final Mac mac;
  private final HmacKey key;

  private boolean finalized = false;

  ChunkedHmacComputation(HmacKey key) throws GeneralSecurityException {
    mac = EngineFactory.MAC.getInstance(composeAlgorithmName(key));
    mac.init(
        new SecretKeySpec(
            key.getKeyBytes().toByteArray(InsecureSecretKeyAccess.get()), "HMAC"));
    this.key = key;
  }

  @Override
  public void update(ByteBuffer data) {
    if (finalized) {
      throw new IllegalStateException(
          "Cannot update after computing the MAC tag. Please create a new object.");
    }
    mac.update(data);
  }

  @Override
  public byte[] computeMac() throws GeneralSecurityException {
    if (finalized) {
      throw new IllegalStateException(
          "Cannot compute after already computing the MAC tag. Please create a new object.");
    }
    if (key.getParameters().getVariant() == Variant.LEGACY) {
      update(ByteBuffer.wrap(FORMAT_VERSION));
    }
    finalized = true;
    return Bytes.concat(
        key.getOutputPrefix().toByteArray(),
        Arrays.copyOf(mac.doFinal(), key.getParameters().getCryptographicTagSizeBytes()));
  }

  private static String composeAlgorithmName(HmacKey key) {
    return "HMAC" + key.getParameters().getHashType();
  }
}
