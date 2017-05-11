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
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.SignatureException;

/**
 * Ed25519 verifying.
 *
 * Usage:
 * // get the publicKey from the other party.
 * Ed25519Verify verifier = new Ed25519Verify(publicKey);
 * try {
 *   verifier.verify(signature, message);
 * } catch (SignatureException se) {
 *   // handle signature check failure.
 * } catch (GeneralSecurityException e) {
 *   // all the rest of security exceptions.
 * }
 */
@Immutable
public final class Ed25519Verify implements PublicKeyVerify {

  public static final int PUBLIC_KEY_LEN = Curve25519.FIELD_LEN;
  public static final int SIGNATURE_LEN = Curve25519.FIELD_LEN * 2;

  private final ImmutableByteArray publicKey;

  public Ed25519Verify(final byte[] publicKey)
      throws GeneralSecurityException {
    if (publicKey.length != PUBLIC_KEY_LEN) {
      throw new IllegalArgumentException(
          String.format("Given public key's length is not %s.", PUBLIC_KEY_LEN));
    }
    this.publicKey = ImmutableByteArray.of(publicKey);
  }

  @Override
  public void verify(byte[] signature, byte[] data) throws GeneralSecurityException {
    if (signature.length != SIGNATURE_LEN) {
      throw new IllegalArgumentException(
          String.format("The length of the signature is not %s.", SIGNATURE_LEN));
    }
    if (((signature[SIGNATURE_LEN - 1] & 0xff) & 224) != 0) {
      throw new IllegalArgumentException("Given signature's 3 most significant bits must be 0.");
    }
    if (!Ed25519.verify(data, signature, publicKey.getBytes())) {
      throw new SignatureException("Signature check failed.");
    }
  }
}
