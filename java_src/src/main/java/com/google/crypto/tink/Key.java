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
import javax.annotation.Nullable;

/**
 * Represents a cryptographic object.
 *
 * <p>In Tink, {@code Key} objects are objects which represent some cryptographic functions. For
 * example, a {@code MacKey} represents the two functions {@code computeMac} and {@code verifyMac}.
 * The function {@code computeMac} maps a byte sequence (possibly with additional randomness) to
 * another byte sequence, called the tag. The function {@code verifyMac} verifies the tag. A
 * subclass {@code HmacKey} then contains all the information one needs to properly compute an HMAC
 * (including e.g. the hash function and tag length used).
 *
 * <p>Key objects are light weight, i.e., they should have almost no dependencies, except what is
 * needed to <em>represent</em> the function. This allows key objects to be used in contexts where
 * dependencies need to be kept at a minimum.
 */
@Immutable
@Alpha
public abstract class Key {
  /**
   * Returns a {@link KeyFormat} object containing all the information about the key which is not
   * randomly chosen.
   *
   * <p>Implementations need to ensure that {@code getKeyFormat().hasIdRequirement()} returns true
   * if and only if {@code getIdRequirementOrNull} is non-null.
   */
  public abstract KeyFormat getKeyFormat();

  /**
   * Returns null if this key has no id requirement, otherwise the required id.
   *
   * <p>Some keys, when they are in a keyset, are required to have a certain ID to work properly.
   * This comes from the fact that Tink in some cases prefixes ciphertexts or signatures with the
   * string {@code 0x01<id>}, where the ID is encoded in big endian (see the documentation of the
   * key type for details), in which case the key requires a certain ID.
   */
  @Nullable
  public abstract Integer getIdRequirementOrNull();

  /**
   * Returns true if the key is equal to the passed in key.
   *
   * <p>Implementations are required to do this in constant time.
   *
   * <p>Note: Tink {@code Key} objects should typically not override {@code hashCode} (because it
   * could risk leaking key material). Hence, they typically also should not override {@code
   * equals}.
   */
  public abstract boolean equalsKey(Key other);
}
