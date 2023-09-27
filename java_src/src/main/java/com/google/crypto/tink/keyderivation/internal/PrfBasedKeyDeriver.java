// Copyright 2023 Google LLC
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

package com.google.crypto.tink.keyderivation.internal;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.internal.MutableKeyDerivationRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationKey;
import com.google.crypto.tink.subtle.prf.StreamingPrf;
import com.google.errorprone.annotations.Immutable;
import java.io.InputStream;
import java.security.GeneralSecurityException;

/**
 * Implements the KeyDeriver interface by first applying a Prf and then using the global registry to
 * create the correct key.
 */
@Immutable
public final class PrfBasedKeyDeriver implements KeyDeriver {
  final StreamingPrf prf;
  final PrfBasedKeyDerivationKey key;

  private PrfBasedKeyDeriver(StreamingPrf prf, PrfBasedKeyDerivationKey key) {
    this.prf = prf;
    this.key = key;
  }

  @AccessesPartialKey
  public static KeyDeriver create(PrfBasedKeyDerivationKey key) throws GeneralSecurityException {
    StreamingPrf prf =
        MutablePrimitiveRegistry.globalInstance().getPrimitive(key.getPrfKey(), StreamingPrf.class);
    PrfBasedKeyDeriver deriver = new PrfBasedKeyDeriver(prf, key);
    Object unused = deriver.deriveKey(new byte[] {1});
    return deriver;
  }

  @Override
  @AccessesPartialKey
  public Key deriveKey(byte[] salt) throws GeneralSecurityException {
    InputStream inputStream = prf.computePrf(salt);
    return MutableKeyDerivationRegistry.globalInstance()
        .createKeyFromRandomness(
            key.getParameters().getDerivedKeyParameters(),
            inputStream,
            key.getIdRequirementOrNull(),
            InsecureSecretKeyAccess.get());
  }
}
