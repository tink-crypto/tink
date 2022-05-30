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

package com.google.crypto.tink.subtle;

import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.ByteArray;
import java.security.GeneralSecurityException;

/**
 * Ed25519 verifying.
 *
 * <h3>Usage</h3>
 *
 * <pre>{@code
 * // get the publicKey from the other party.
 * Ed25519Verify verifier = new Ed25519Verify(publicKey);
 * try {
 *   verifier.verify(signature, message);
 * } catch (GeneralSecurityException e) {
 *   // all the rest of security exceptions.
 * }
 * }</pre>
 *
 * @since 1.1.0
 */
public final class Ed25519Verify implements PublicKeyVerify {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  public static final int PUBLIC_KEY_LEN = Field25519.FIELD_LEN;
  public static final int SIGNATURE_LEN = Field25519.FIELD_LEN * 2;

  private final ByteArray publicKey;

  public Ed25519Verify(final byte[] publicKey) {
    if (!FIPS.isCompatible()) {
      // This should be a GenericSecurityException, however as external users rely on this
      // constructor not throwing a GenericSecurityException we use a runtime exception here
      // instead.
      throw new IllegalStateException(
          new GeneralSecurityException("Can not use Ed25519 in FIPS-mode."));
    }

    if (publicKey.length != PUBLIC_KEY_LEN) {
      throw new IllegalArgumentException(
          String.format("Given public key's length is not %s.", PUBLIC_KEY_LEN));
    }
    this.publicKey = ByteArray.copyFrom(publicKey);
  }

  @Override
  public void verify(byte[] signature, byte[] data) throws GeneralSecurityException {
    if (signature.length != SIGNATURE_LEN) {
      throw new GeneralSecurityException(
          String.format("The length of the signature is not %s.", SIGNATURE_LEN));
    }
    if (!Ed25519.verify(data, signature, publicKey.toByteArray())) {
      throw new GeneralSecurityException("Signature check failed.");
    }
  }
}
