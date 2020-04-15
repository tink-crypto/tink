// Copyright 2018 Google Inc.
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
 * Interface for symmetric Key wrapping.
 * A key wrap algorithm is a primitive specifically meant for encrypting
 * key material. Primitives implementing the interface may either be
 * deterministic or non-deterministic.
 *
 * The interface is somewhat limited. It does not allow additional
 * data during key wrapping. The security guarantees are not including
 * a multi user setting. The reason for these limitations is that
 * it allows to include KWP, with the plan to allow rotation to other
 * algorithms.
 *
 * <h2>Requirements</h2>
 * Primitives implementing use key sizes of 128-bits or higher.
 * Key wrapping includes an integrity check.
 * The minimal strength of the integrity check is about 64 bits.
 * In particular, the minimal key strength allows KWP to be included.
 *
 * <h2>Key size of the wrapped key.</h2>
 * Valid key sizes are in the range 16 .. 4096 bytes.
 * The lower bound assures a low probability of key collisions,
 * and hence allows deterministic key wrappings to be used.
 *
 * @since 1.?.?
 */
public interface KeyWrap {
  /**
   * Wraps some key material {@code data}.
   *
   * @param data the key to wrap. 
   * @return the wrapped key
   */
  byte[] wrap(final byte[] data) throws GeneralSecurityException;

  /**
   * Unwraps a wrapped key.
   *
   * @throws GeneralSecurityException if {@code data} fails the integrity check.
   */
  byte[] unwrap(final byte[] data) throws GeneralSecurityException;
}
