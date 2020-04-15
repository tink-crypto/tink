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
 * Interface for Message Authentication Codes (MAC).
 *
 * <h3>Security guarantees</h3>
 *
 * <p>Message Authentication Codes provide symmetric message authentication. Instances implementing
 * this interface are secure against existential forgery under chosen plaintext attack, and can be
 * deterministic or randomized. This interface should be used for authentication only, and not for
 * other purposes like generation of pseudorandom bytes.
 *
 * @since 1.0.0
 */
public interface Mac {
  /**
   * Computes message authentication code (MAC) for {@code data}.
   *
   * @return MAC value
   */
  byte[] computeMac(final byte[] data) throws GeneralSecurityException;

  /**
   * Verifies whether {@code mac} is a correct authentication code (MAC) for {@code data}.
   *
   * @throws GeneralSecurityException if {@code mac} is not a correct MAC for {@code data}
   */
  void verifyMac(final byte[] mac, final byte[] data) throws GeneralSecurityException;
}
