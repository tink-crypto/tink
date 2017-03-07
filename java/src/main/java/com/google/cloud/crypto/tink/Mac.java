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

package com.google.cloud.crypto.tink;

import java.security.GeneralSecurityException;

/**
 * Interface for MACs (Message Authentication Codes).
 * This interface should be used for authentication only, and not for other purposes
 * (for example, it should not be used to generate pseudorandom bytes).
 */
public interface Mac {
  /**
   * Computes message authentication code (MAC) for {@code data}.
   *
   * @return MAC value.
   */
  byte[] computeMac(final byte[] data) throws GeneralSecurityException;

  /**
   * Verifies whether {@code mac} is a correct authentication code (MAC) for {@code data}.
   *
   * @throws GeneralSecurityException If {@code mac} is not a correct MAC for {@code data} then a
   * GeneralSecurityException is thrown.
   */
  void verifyMac(final byte[] mac, final byte[] data) throws GeneralSecurityException;
}
