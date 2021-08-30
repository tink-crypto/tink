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

import com.google.crypto.tink.annotations.Alpha;
import java.security.InvalidKeyException;
import java.util.Arrays;

/**
 * Defines <a href="https://cr.yp.to/ecdh/curve25519-20060209.pdf">the ECDH Curve25519 function</a>,
 * also known as the X25519 function.
 *
 * <p>This implementation is based on <a
 * href="https://github.com/agl/curve25519-donna/blob/master/curve25519-donna.c">curve255-donna</a>.
 *
 * <h3>Warning</h3>
 *
 * <p>Do not use this API or any other APIs including fields and methods marked with the @Alpha
 * annotation. They can be modified in any way, or even removed, at any time. They are in the
 * package, but not for official, production release, but only for testing.
 *
 * <h3>Usage</h3>
 *
 * <pre>
 * Alice:
 * byte[] privateKeyA = X25519.generatePrivateKey();
 * byte[] publicKeyA = X25519.publicFromPrivate(privateKeyA);
 * Bob:
 * byte[] privateKeyB = X25519.generatePrivateKey();
 * byte[] publicKeyB = X25519.publicFromPrivate(privateKeyB);
 *
 * Alice sends publicKeyA to Bob and Bob sends publicKeyB to Alice.
 * Alice:
 * byte[] sharedSecretA = X25519.computeSharedSecret(privateKeyA, publicKeyB);
 * Bob:
 * byte[] sharedSecretB = X25519.computeSharedSecret(privateKeyB, publicKeyA);
 * such that sharedSecretA == sharedSecretB.
 * </pre>
 */
@Alpha
public final class X25519 {
  /**
   * Returns a 32-byte private key for Curve25519.
   *
   * <p>Note from BoringSSL: All X25519 implementations should decode scalars correctly (see
   * https://tools.ietf.org/html/rfc7748#section-5). However, if an implementation doesn't then it
   * might interoperate with random keys a fraction of the time because they'll, randomly, happen to
   * be correctly formed.
   *
   * <p>Thus we do the opposite of the masking here to make sure that our private keys are never
   * correctly masked and so, hopefully, any incorrect implementations are deterministically broken.
   *
   * <p>This does not affect security because, although we're throwing away entropy, a valid
   * implementation of computeSharedSecret should throw away the exact same bits anyway.
   */
  @SuppressWarnings("NarrowingCompoundAssignment")
  public static byte[] generatePrivateKey() {
    byte[] privateKey = Random.randBytes(Field25519.FIELD_LEN);

    privateKey[0] |= 7;
    privateKey[31] &= 63;
    privateKey[31] |= 128;

    return privateKey;
  }

  /**
   * Returns the 32-byte shared key (i.e., privateKey·peersPublicValue on the curve).
   *
   * @param privateKey 32-byte private key
   * @param peersPublicValue 32-byte public value
   * @return the 32-byte shared key
   * @throws InvalidKeyException when {@code privateKey} is not 32-byte or {@code peersPublicValue}
   *     is invalid.
   */
  @SuppressWarnings("NarrowingCompoundAssignment")
  public static byte[] computeSharedSecret(byte[] privateKey, byte[] peersPublicValue)
      throws InvalidKeyException {
    if (privateKey.length != Field25519.FIELD_LEN) {
      throw new InvalidKeyException("Private key must have 32 bytes.");
    }
    long[] x = new long[Field25519.LIMB_CNT + 1];

    byte[] e = Arrays.copyOf(privateKey, Field25519.FIELD_LEN);
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    Curve25519.curveMult(x, e, peersPublicValue);
    return Field25519.contract(x);
  }

  /**
   * Returns the 32-byte Diffie-Hellman public value based on the given {@code privateKey} (i.e.,
   * {@code privateKey}·[9] on the curve).
   *
   * @param privateKey 32-byte private key
   * @return 32-byte Diffie-Hellman public value
   * @throws InvalidKeyException when the {@code privateKey} is not 32 bytes.
   */
  public static byte[] publicFromPrivate(byte[] privateKey) throws InvalidKeyException {
    if (privateKey.length != Field25519.FIELD_LEN) {
      throw new InvalidKeyException("Private key must have 32 bytes.");
    }
    byte[] base = new byte[Field25519.FIELD_LEN];
    base[0] = 9;
    return computeSharedSecret(privateKey, base);
  }

  private X25519() {}
}
