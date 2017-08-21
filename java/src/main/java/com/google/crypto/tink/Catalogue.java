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

package com.google.crypto.tink;

import java.security.GeneralSecurityException;

/**
 * A catalogue of key managers.  It is basically a map from a (key type,
 * primitive name)-tuple to {@code KeyManager}-objects, that determine
 * the implementation that handles the keys of the given key type.
 *
 * <p>Tink comes with per-primitive default catalogues ({@link AeadCatalogue},
 * {@link MacCatalogue}, {@link HybridCatalogue}, and {@link SignatureCatalogue}),
 * but supports custom catalogues to enable user-defined configuration
 * of run-time environment via {@link Registry}.
 */
public interface Catalogue {
  /**
   * @return a KeyManager for the given {@code typeUrl}, {@code primitiveName},
   * and version at least {@code minVersion} (if it exists in the catalogue).
   */
  @SuppressWarnings("rawtypes")
  public KeyManager getKeyManager(String typeUrl, String primitiveName, int minVersion)
      throws GeneralSecurityException;
}
