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

package com.google.crypto.tink.keyderivation;

import java.security.GeneralSecurityException;

/**
 * KeysetDeriverWrapper is the implementation of PrimitiveWrapper for the KeysetDeriver primitive.
 *
 * <p>The wrapper derives a key from each key in a keyset, and returns the resulting keys as a new
 * keyset. Each of the derived keys inherits key_id, status, and output_prefix_type from the key
 * from which it was derived.
 */
public final class KeysetDeriverWrapper {
  /**
   * Registers this wrapper with Tink, allowing to use the primitive.
   *
   * @deprecated Call KeyDerivationConfig.register() instead.
   */
  @Deprecated
  public static void register() throws GeneralSecurityException {
    com.google.crypto.tink.keyderivation.internal.KeysetDeriverWrapper.register();
  }

  private KeysetDeriverWrapper() {}
}
