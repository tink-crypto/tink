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

package com.google.crypto.tink.keyderivation;

import com.google.crypto.tink.Key;

/**
 * Represents a function to derive a key.
 *
 * <p>Tink Key Derivation is given by the primitive which maps a {@code byte[] salt} to a Keyset.
 * For each key, a {@link KeyDerivationKey} maps a {@code byte[] salt} to a new "derived" {@code
 * Key}. For a Keyset containing multiple derivation keys, the derived keyset is obtained by mapping
 * each key according to this map (for the same {@code byte[] salt}), and inserting them into a new
 * keyset.
 */
public abstract class KeyDerivationKey extends Key {
  @Override
  public abstract KeyDerivationParameters getParameters();
}
