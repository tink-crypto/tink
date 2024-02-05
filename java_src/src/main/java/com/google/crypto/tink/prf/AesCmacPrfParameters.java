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

package com.google.crypto.tink.prf;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Objects;

/** Describes the parameters of an {@link AesCmacPrfKey}. */
public final class AesCmacPrfParameters extends PrfParameters {
  public static AesCmacPrfParameters create(int keySizeBytes) throws GeneralSecurityException {
    if (keySizeBytes != 16 && keySizeBytes != 32) {
      throw new InvalidAlgorithmParameterException(
          String.format(
              "Invalid key size %d; only 128-bit and 256-bit are supported", keySizeBytes * 8));
    }
    return new AesCmacPrfParameters(keySizeBytes);
  }

  private final int keySizeBytes;

  private AesCmacPrfParameters(int keySizeBytes) {
    this.keySizeBytes = keySizeBytes;
  }

  public int getKeySizeBytes() {
    return keySizeBytes;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof AesCmacPrfParameters)) {
      return false;
    }
    AesCmacPrfParameters that = (AesCmacPrfParameters) o;
    return that.getKeySizeBytes() == getKeySizeBytes();
  }

  @Override
  public int hashCode() {
    return Objects.hash(AesCmacPrfParameters.class, keySizeBytes);
  }

  @Override
  public boolean hasIdRequirement() {
    return false;
  }

  @Override
  public String toString() {
    return "AesCmac PRF Parameters (" + keySizeBytes + "-byte key)";
  }
}
