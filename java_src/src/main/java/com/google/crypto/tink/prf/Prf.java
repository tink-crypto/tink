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

/**
 * The PRF interface is an abstraction for an element of a pseudo random function family, selected
 * by a key. It has the following properties:
 *
 * <p>- It is deterministic: PRF.compute(input, length) will always return the same output if the
 * same key is used. PRF.compute(input, length1) will be a prefix of PRF.compute(input, length2) if
 * length1 < length2 and the same key is used. - It is indistinguishable from a random function:
 * Given the evaluation of n different inputs, an attacker cannot distinguish between the PRF and
 * random bytes on an input different from the n that are known.
 *
 * <p>Use cases for PRF are deterministic redaction of PII, keyed hash functions, creating sub IDs
 * that do not allow joining with the original dataset without knowing the key. While PRFs can be
 * used in order to prove authenticity of a message, using the MAC interface is recommended for that
 * use case, as it has support for verification, avoiding the security problems that often happen
 * during verification. It also allows for non-deterministic MAC algorithms.
 */
@Immutable
public interface Prf {
  /**
   * Computes the PRF selected by the underlying key on input and returns the first outputLength
   * bytes.
   *
   * @param input the input to compute the PRF on.
   * @param outputLength the desired length of the output in bytes. When choosing this parameter
   *     keep the birthday paradox in mind. If you have 2^n different inputs that your system has to
   *     handle set the output length to ceil(n/4 + 4) This corresponds to 2*n + 32 bits, meaning a
   *     collision will occur with a probability less than 1:2^32. When in doubt, request a security
   *     review.
   * @throws GeneralSecurityException if the algorithm fails or if the output of algorithm is less
   *     than outputLength.
   */
  byte[] compute(byte[] input, int outputLength) throws GeneralSecurityException;
}
