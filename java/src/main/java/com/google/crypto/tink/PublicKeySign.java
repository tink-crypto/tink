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
 * Interface for public key signing.
 *
 * <p>Digital Signatures provide functionality of signing data and verification of the signatures.
 *
 * <p>The functionality of Digital Signatures is represented a pair of primitives (interfaces)
 * {@link PublicKeySign} for signing of data, and {@link PublicKeyVerify} for verification of
 * signatures.
 *
 * <p>Implementations of these interfaces are secure against adaptive chosen-message attacks.
 * Signing data ensures the authenticity and the integrity of that data, but not its secrecy.
 */
public interface PublicKeySign {
  /**
   * Computes the signature for {@code data}.
   *
   * @return the signature of {$code data}
   */
  byte[] sign(final byte[] data) throws GeneralSecurityException;
}
