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
package com.google.crypto.tink.subtle.prf;

import com.google.errorprone.annotations.Immutable;
import java.io.InputStream;

/**
 * Streaming API Interface for Pseudo Random Function (Prf)
 *
 * <h3>Security guarantees</h3>
 *
 * <p>Pseudorandom functions provide a mapping from an input to an output string which is
 * indistinguishable from a pure random function.
 *
 * <p>In Tink, the pseudorandom interface produces a stream of pseudorandom bytes, from which the
 * user can read. The resulting stream may be of (virtually) infinite length, producing bytes as
 * long as the user reads from it, or it may produce a finite length stream of a certain length.
 * More formally, ignoring timing, every implementation is indistinguishable in the input/output
 * behavior from the following ideal implementation, for some length {@code LENGTH}.
 * <pre>{@code
 *   public class IdealPRF {
 *     private Map<byte[], byte[]> cache = new ArrayMap<>();
 *     private static final int LENGTH = ...; // Any value; conceptually, Infinite would also be ok.
 *
 *     public InputStream apply(final byte[] input) {
 *       if (!cache.containsKey(input)) {
 *         cache.put(input, Random.getBytes(LENGTH)));
 *       }
 *       return new ByteArrayInputStream(cache.get(input));
 *     }
 *   }
 * }</pre>
 */
@Immutable
public interface StreamingPrf {
  /**
   * Returns an {@link InputStream} which is indistinguishable from a stream returning random bytes
   * in the above sense.
   */
  InputStream computePrf(final byte[] input);
}
