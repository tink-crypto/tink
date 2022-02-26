// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.hybrid.internal;

import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;

/**
 * Interface for Hybrid Public Key Encryption (HPKE) key derivation function (KDF).
 *
 * <p>HPKE RFC is available at https://www.rfc-editor.org/rfc/rfc9180.html.
 */
@Immutable
interface HpkeKdf {
  /**
   * Extracts pseudorandom key from {@code salt} and {@code ikm} using the HPKE-specific values
   * {@code ikmLabel} and {@code suiteId} to facilitate domain separation and context binding.
   *
   * <p>More details available at https://www.rfc-editor.org/rfc/rfc9180.html#section-4-9.
   *
   * @param salt optional (possibly non-secret) random value
   * @param ikm input keying material
   * @param ikmLabel label prepended to {@code ikm}
   * @param suiteId HPKE cipher suite identifier prepended to { {@code ikmLabel} || {@code ikm} }
   * @return pseudorandom key
   */
  byte[] labeledExtract(byte[] salt, byte[] ikm, String ikmLabel, byte[] suiteId)
      throws GeneralSecurityException;

  /**
   * Expands pseudorandom key {@code prk} into {@code length} pseudorandom bytes using {@code info}
   * along with the HPKE-specific values {@code infoLabel} and {@code suiteId} to facilitate domain
   * separation and context binding.
   *
   * <p>More details available at https://www.rfc-editor.org/rfc/rfc9180.html#section-4-10.
   *
   * @param prk pseudorandom key
   * @param info optional context and application-specific information
   * @param infoLabel label prepended to {@code info}
   * @param suiteId HPKE cipher suite identifier prepended to { {@code infoLabel} || {@code info} }
   * @param length desired length (in bytes) of pseudorandom output
   * @return {@code length} pseudorandom bytes of output keying material
   */
  byte[] labeledExpand(byte[] prk, byte[] info, String infoLabel, byte[] suiteId, int length)
      throws GeneralSecurityException;

  /**
   * Combines {@link #labeledExtract(byte[], byte[], String, byte[])} and {@link
   * #labeledExpand(byte[], byte[], String, byte[], int)} into a single method.
   *
   * <p>More details available at https://www.rfc-editor.org/rfc/rfc9180.html#section-4.1-3.
   *
   * @param salt optional (possibly non-secret) random value
   * @param ikm input keying material
   * @param ikmLabel label prepended to {@code ikm}
   * @param info optional context and application-specific information
   * @param infoLabel label prepended to {@code info}
   * @param suiteId HPKE cipher suite identifier prepended to { {@code ikmLabel} || {@code ikm} }
   *     and { {@code infoLabel} || {@code info} }
   * @param length desired length (in bytes) of pseudorandom output
   * @return {@code length} pseudorandom bytes of output keying material
   */
  byte[] extractAndExpand(
      byte[] salt,
      byte[] ikm,
      String ikmLabel,
      byte[] info,
      String infoLabel,
      byte[] suiteId,
      int length)
      throws GeneralSecurityException;

  /**
   * Returns the HPKE KDF algorithm identifier for the underlying KDF implementation.
   *
   * <p>More details at
   * https://www.rfc-editor.org/rfc/rfc9180.html#name-key-derivation-functions-kd.
   */
  byte[] getKdfId() throws GeneralSecurityException;
}
