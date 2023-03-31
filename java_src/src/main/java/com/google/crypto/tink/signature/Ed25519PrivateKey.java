// Copyright 2023 Google LLC
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

package com.google.crypto.tink.signature;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.annotations.Alpha;
import com.google.crypto.tink.internal.Ed25519;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.Immutable;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * The key for computing Ed25519 signatures.
 *
 * <p>This API is annotated with Alpha because it is not yet stable and might be changed in the
 * future.
 */
@Alpha
@Immutable
public final class Ed25519PrivateKey extends SignaturePrivateKey {
  private final Ed25519PublicKey publicKey;
  private final SecretBytes privateKeyBytes;

  private Ed25519PrivateKey(Ed25519PublicKey publicKey, SecretBytes privateKeyBytes) {
    this.publicKey = publicKey;
    this.privateKeyBytes = privateKeyBytes;
  }

  @AccessesPartialKey
  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public static Ed25519PrivateKey create(Ed25519PublicKey publicKey, SecretBytes privateKeyBytes)
      throws GeneralSecurityException {
    if (publicKey == null) {
      throw new GeneralSecurityException(
          "Ed25519 key cannot be constructed without an Ed25519 public key");
    }
    if (privateKeyBytes.size() != 32) {
      throw new GeneralSecurityException(
          "Ed25519 key must be constructed with key of length 32 bytes, not "
              + privateKeyBytes.size());
    }

    // Validate private key based on the public key bytes.
    byte[] publicKeyBytes =
        publicKey.getPublicKeyBytes().toByteArray(InsecureSecretKeyAccess.get());
    byte[] secretSeed = privateKeyBytes.toByteArray(InsecureSecretKeyAccess.get());
    byte[] expectedPublicKeyBytes =
        Ed25519.scalarMultWithBaseToBytes(Ed25519.getHashedScalar(secretSeed));

    if (!Arrays.equals(publicKeyBytes, expectedPublicKeyBytes)) {
      throw new GeneralSecurityException("Ed25519 keys mismatch");
    }

    return new Ed25519PrivateKey(publicKey, privateKeyBytes);
  }

  @Override
  public Ed25519Parameters getParameters() {
    return publicKey.getParameters();
  }

  @Override
  public Ed25519PublicKey getPublicKey() {
    return publicKey;
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public SecretBytes getPrivateKeyBytes() {
    return privateKeyBytes;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof Ed25519PrivateKey)) {
      return false;
    }
    Ed25519PrivateKey that = (Ed25519PrivateKey) o;
    return that.publicKey.equalsKey(publicKey)
        && privateKeyBytes.equalsSecretBytes(that.privateKeyBytes);
  }
}
