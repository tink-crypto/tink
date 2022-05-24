// Copyright 2022 Google LLC
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

import com.google.crypto.tink.annotations.Alpha;
import com.google.errorprone.annotations.Immutable;

/**
 * Represents a cryptographic function without the actual key material.
 *
 * <p>In Tink, a Key represents a set of cryptographic functions. The KeyFormat class contains all
 * the information about the function which is not randomly chosen with each instance.
 */
@Immutable
@Alpha
public abstract class KeyFormat {
  /**
   * Returns true if a key created with this format has to have a certain ID when it is in a keyset.
   *
   * <p>In Tink, certain keys change their behavior depending on the key id (for example, an {@link
   * Aead} object can prefix the ciphertext with the big endian encoding of the key id). If this is
   * the case, such a key should require a unique id in {@link Key#getIdRequirement} and return
   * true here.
   */
  public abstract boolean hasIdRequirement();
}
