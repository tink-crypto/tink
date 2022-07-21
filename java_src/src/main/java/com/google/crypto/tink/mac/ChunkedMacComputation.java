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

package com.google.crypto.tink.mac;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/**
 * An interface representing a computation of the Streaming MAC.
 *
 * <p>WARNING: Implementations of this interface are not thread-safe, so the caller must ensure
 * correctness in case of concurrent use of an instance of this class.
 */
public interface ChunkedMacComputation {
  /**
   * Processes the next chunk of input, represented by {@code ByteBuffer data}.
   * In particular, reads the {@code data.remaining()} number of bytes from the provided buffer,
   * starting at the byte with position {@code data.position()}.
   * 
   * <p>Updates the inner state of the computation. Requires exclusive access.
   *
   * <p>NOTE: arbitrary slicing of data is permitted, i.e. a series of {@code update()}'s with
   * inputs {@code "ab"}, {@code "cd"}, and {@code "ef"} produces the same result as a series of
   * inputs {@code "abc"}, {@code "def"}.
   *
   * @throws IllegalStateException if called after computeMac()
   * @throws GeneralSecurityException when something went wrong with the update
   */
  void update(ByteBuffer data) throws GeneralSecurityException;

  /**
   * Computes a tag for the provided data. After this method has been called, the object can no
   * longer be used.
   *
   * <p>Requires exclusive access.
   *
   * @throws IllegalStateException when called more than once
   * @throws GeneralSecurityException when something went wrong with the computation
   */
  byte[] computeMac() throws GeneralSecurityException;
}
