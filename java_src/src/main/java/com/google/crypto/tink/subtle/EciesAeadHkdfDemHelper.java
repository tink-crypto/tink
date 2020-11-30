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

package com.google.crypto.tink.subtle;

import com.google.crypto.tink.hybrid.subtle.AeadOrDaead;
import java.security.GeneralSecurityException;

/**
 * A helper for DEM (data encapsulation mechanism) of ECIES-AEAD-HKDF.
 *
 * @since 1.0.0
 */
public interface EciesAeadHkdfDemHelper {
  /** @return the size of the DEM-key in bytes. */
  public int getSymmetricKeySizeInBytes();

  /**
   * Creates a new {@code AeadOrDaead}-primitive that uses the key material given in
   * 'symmetric_key', which must be of length dem_key_size_in_bytes().
   *
   * @return the newly created {@code AeadOrDaead}-primitive.
   */
  public AeadOrDaead getAeadOrDaead(final byte[] symmetricKeyValue) throws GeneralSecurityException;
}
