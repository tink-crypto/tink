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

import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Map;

/**
 * A Tink Keyset can be converted into a set of PRFs using this primitive. Every key in the keyset
 * corresponds to a PRF in the PRFSet. Every PRF in the set is given an ID, which is the same ID as
 * the key id in the Keyset.
 */
@Immutable
public abstract class PrfSet {
  /** Returns the primary ID of the keyset. */
  public abstract int getPrimaryId();

  /**
   * A map of the PRFs represented by the keys in this keyset. The map is guaranteed to contain
   * getPrimaryId() as a key.
   */
  public abstract Map<Integer, Prf> getPrfs() throws GeneralSecurityException;

  /**
   * Convenience method to compute the primary PRF on a given input. See PRF.compute for details of
   * the parameters.
   */
  public byte[] computePrimary(byte[] input, int outputLength) throws GeneralSecurityException {
    return getPrfs().get(getPrimaryId()).compute(input, outputLength);
  }
}
