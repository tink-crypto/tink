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
 * Interface for Hybrid Public Key Encryption (HPKE) key encapsulation mechanism (KEM).
 *
 * <p>HPKE I.-D. is available at https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-11.html.
 */
@Immutable
public interface HpkeKem {
  /**
   * Generates and encapsulates a shared secret using the {@code recipientPublicKey}. Returns a
   * {@link com.google.crypto.tink.hybrid.internal.HpkeKemEncapOutput} object that contains the raw
   * shared secret and the encapsulated key. The HPKE I.-D. refers to this method as Encap(), which
   * is used by the sender.
   *
   * @throws GeneralSecurityException when either the shared secret cannot be generated or the
   * shared secret cannot be encapsulated.
   */
  public HpkeKemEncapOutput encapsulate(byte[] recipientPublicKey) throws GeneralSecurityException;

  /**
   * Extracts the shared secret from {@code encapsulatedKey} using {@code recipientPrivateKey}.
   * Returns the raw shared secret. The HPKE I.-D. refers to this method as Decap(), which is used
   * by the recipient.
   *
   * @throws GeneralSecurityException if the shared secret cannot be extracted.
   */
  public byte[] decapsulate(byte[] encapsulatedKey, byte[] recipientPrivateKey)
      throws GeneralSecurityException;

  /**
   * Returns the HPKE KEM algorithm identifier for the underlying KEM implementation.
   *
   * <p>More details at
   * https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#name-key-encapsulation-mechanism.
   */
  public byte[] getKemId() throws GeneralSecurityException;
}
