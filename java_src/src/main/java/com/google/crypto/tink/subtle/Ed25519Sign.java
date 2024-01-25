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

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.Ed25519;
import com.google.crypto.tink.internal.Field25519;
import com.google.crypto.tink.signature.Ed25519Parameters;
import com.google.crypto.tink.signature.Ed25519PrivateKey;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Ed25519 signing.
 *
 * <h3>Usage</h3>
 *
 * <pre>{@code
 * Ed25519Sign.KeyPair keyPair = Ed25519Sign.KeyPair.newKeyPair();
 * // securely store keyPair and share keyPair.getPublicKey()
 * Ed25519Sign signer = new Ed25519Sign(keyPair.getPrivateKey());
 * byte[] signature = signer.sign(message);
 * }</pre>
 *
 * @since 1.1.0
 */
public final class Ed25519Sign implements PublicKeySign {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  public static final int SECRET_KEY_LEN = Field25519.FIELD_LEN;

  private final byte[] hashedPrivateKey;
  private final byte[] publicKey;
  private final byte[] outputPrefix;
  private final byte[] messageSuffix;

  @AccessesPartialKey
  public static PublicKeySign create(Ed25519PrivateKey key) throws GeneralSecurityException {
    return new Ed25519Sign(
        key.getPrivateKeyBytes().toByteArray(InsecureSecretKeyAccess.get()),
        key.getOutputPrefix().toByteArray(),
        key.getParameters().getVariant().equals(Ed25519Parameters.Variant.LEGACY)
            ? new byte[] {0}
            : new byte[0]);
  }

  private Ed25519Sign(
      final byte[] privateKey, final byte[] outputPrefix, final byte[] messageSuffix)
      throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException("Can not use Ed25519 in FIPS-mode.");
    }

    if (privateKey.length != SECRET_KEY_LEN) {
      throw new IllegalArgumentException(
          String.format("Given private key's length is not %s", SECRET_KEY_LEN));
    }

    this.hashedPrivateKey = Ed25519.getHashedScalar(privateKey);
    this.publicKey = Ed25519.scalarMultWithBaseToBytes(this.hashedPrivateKey);
    this.outputPrefix = outputPrefix;
    this.messageSuffix = messageSuffix;
  }

  /**
   * Constructs a Ed25519Sign with the {@code privateKey}.
   *
   * @param privateKey 32-byte random sequence.
   * @throws GeneralSecurityException if there is no SHA-512 algorithm defined in {@link
   *     EngineFactory}.MESSAGE_DIGEST.
   */
  public Ed25519Sign(final byte[] privateKey) throws GeneralSecurityException {
    this(privateKey, new byte[0], new byte[0]);
  }

  private byte[] noPrefixSign(final byte[] data) throws GeneralSecurityException {
    return Ed25519.sign(data, publicKey, hashedPrivateKey);
  }

  @Override
  public byte[] sign(final byte[] data) throws GeneralSecurityException {
    byte[] signature;
    if (messageSuffix.length == 0) {
      signature = noPrefixSign(data);
    } else {
      signature = noPrefixSign(Bytes.concat(data, messageSuffix));
    }
    if (outputPrefix.length == 0) {
      return signature;
    } else {
      return Bytes.concat(outputPrefix, signature);
    }
  }

  /** Defines the KeyPair consisting of a private key and its corresponding public key. */
  public static final class KeyPair {

    private final byte[] publicKey;
    private final byte[] privateKey;

    private KeyPair(final byte[] publicKey, final byte[] privateKey) {
      this.publicKey = publicKey;
      this.privateKey = privateKey;
    }

    public byte[] getPublicKey() {
      return Arrays.copyOf(publicKey, publicKey.length);
    }

    public byte[] getPrivateKey() {
      return Arrays.copyOf(privateKey, privateKey.length);
    }

    /** Returns a new <publicKey, privateKey> KeyPair. */
    public static KeyPair newKeyPair() throws GeneralSecurityException {
      return newKeyPairFromSeed(Random.randBytes(Field25519.FIELD_LEN));
    }

    /** Returns a new <publicKey, privateKey> KeyPair generated from a seed. */
    public static KeyPair newKeyPairFromSeed(byte[] secretSeed) throws GeneralSecurityException {
      if (secretSeed.length != Field25519.FIELD_LEN) {
        throw new IllegalArgumentException(
            String.format("Given secret seed length is not %s", Field25519.FIELD_LEN));
      }
      byte[] privateKey = secretSeed;
      byte[] publicKey = Ed25519.scalarMultWithBaseToBytes(Ed25519.getHashedScalar(privateKey));
      return new KeyPair(publicKey, privateKey);
    }
  }
}
