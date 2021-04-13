// Copyright 2018 Google LLC
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

package com.google.crypto.tink.apps.paymentmethodtoken;

import java.security.GeneralSecurityException;

/**
 * Interface for recipient's key encapsulation mechanism (KEM).
 *
 * <p>Google Pay's tokens are encrypted using ECIES which is a hybrid encryption mode consisting of
 * two steps: key encapsulation mechanisam (KEM) using Elliptic Curve Diffie Hellman (ECDH) and HKDF
 * and data encapsulation mechanism (DEM) using AES-CTR-HMAC.
 *
 * <p>During encryption, the KEM step takes the recipient's public key and produces a DEM key and an
 * ephemeral public key. The DEM key is then used to encrypt the credit card data, and the ephemeral
 * public key is sent as the <b>ephemeralPublicKey</b> field of the payload.
 *
 * <p>To decrypt, the recipient must use their private key to compute an ECDH shared secret from the
 * ephemeral public key, and from that derive the DEM key using HKDF. If the recipient keeps the
 * private key in a HSM, they cannot load the private key in Tink, but they can implement this
 * interface and configure Tink to use their custom KEM implementation with {@link
 * PaymentMethodTokenRecipient.Builder#addRecipientKem}.
 *
 * @see <a href="https://developers.google.com/pay/api/payment-data-cryptography">Google Payment
 *     Method Token standard</a>
 * @since 1.1.0
 */
public interface PaymentMethodTokenRecipientKem {
  /**
   * Computes a shared secret from the {@code ephemeralPublicKey}, using ECDH.
   *
   * <p>{@code ephemeralPublicKey} is a point on the elliptic curve defined in the <a
   * href="https://developers.google.com/pay/api/payment-data-cryptography">Google Payment Method
   * Token standard</a>, encoded in uncompressed point format. In version ECv1 and ECv2 of the
   * standard, the elliptic curve is NIST P-256.
   *
   * <p>Note that you only needs to compute the shared secret, but you don't have to derive the DEM
   * key with HKDF -- that process is handled by Tink.
   */
  byte[] computeSharedSecret(final byte[] ephemeralPublicKey) throws GeneralSecurityException;
}
