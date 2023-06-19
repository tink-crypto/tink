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
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.RestrictedApi;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Represents a private key for RSA SSA PSS signatures.
 *
 * <p>Standard: https://www.rfc-editor.org/rfc/rfc8017#section-3.2.
 */
public final class RsaSsaPssPrivateKey extends SignaturePrivateKey {
  private final RsaSsaPssPublicKey publicKey;
  private final SecretBigInteger d;
  private final SecretBigInteger p;
  private final SecretBigInteger q;
  private final SecretBigInteger dP;
  private final SecretBigInteger dQ;
  private final SecretBigInteger qInv;

  /** Builder for RsaSsaPssPrivateKey. */
  public static class Builder {
    @Nullable private RsaSsaPssPublicKey publicKey = null;
    @Nullable private SecretBigInteger d = null;
    @Nullable private SecretBigInteger p = null;
    @Nullable private SecretBigInteger q = null;
    @Nullable private SecretBigInteger dP = null;
    @Nullable private SecretBigInteger dQ = null;
    @Nullable private SecretBigInteger qInv = null;

    private Builder() {}

    /**
     * Sets the public key, which includes the parameters.
     *
     * <p>This is required.
     */
    @CanIgnoreReturnValue
    public Builder setPublicKey(RsaSsaPssPublicKey publicKey) {
      this.publicKey = publicKey;
      return this;
    }

    /**
     * Sets the prime factors p and q.
     *
     * <p>This is required.
     */
    @CanIgnoreReturnValue
    public Builder setPrimes(SecretBigInteger p, SecretBigInteger q) {
      this.p = p;
      this.q = q;
      return this;
    }

    /**
     * Sets the private exponent d.
     *
     * <p>This is required.
     */
    @CanIgnoreReturnValue
    public Builder setPrivateExponent(SecretBigInteger d) {
      this.d = d;
      return this;
    }

    /**
     * Sets the prime exponents dP and dQ.
     *
     * <p>See https://www.rfc-editor.org/rfc/rfc8017#section-3.2.
     *
     * <p>This is required.
     */
    @CanIgnoreReturnValue
    public Builder setPrimeExponents(SecretBigInteger dP, SecretBigInteger dQ) {
      this.dP = dP;
      this.dQ = dQ;
      return this;
    }

    /**
     * Sets the CRT coefficient qInv.
     *
     * <p>See https://www.rfc-editor.org/rfc/rfc8017#section-3.2.
     *
     * <p>This is required.
     */
    @CanIgnoreReturnValue
    public Builder setCrtCoefficient(SecretBigInteger qInv) {
      this.qInv = qInv;
      return this;
    }

    private static final int PRIME_CERTAINTY = 10;

    @AccessesPartialKey
    public RsaSsaPssPrivateKey build() throws GeneralSecurityException {
      if (publicKey == null) {
        throw new GeneralSecurityException("Cannot build without a RSA SSA PKCS1 public key");
      }
      if (p == null || q == null) {
        throw new GeneralSecurityException("Cannot build without prime factors");
      }
      if (d == null) {
        throw new GeneralSecurityException("Cannot build without private exponent");
      }
      if (dP == null || dQ == null) {
        throw new GeneralSecurityException("Cannot build without prime exponents");
      }
      if (qInv == null) {
        throw new GeneralSecurityException("Cannot build without CRT coefficient");
      }
      BigInteger e = publicKey.getParameters().getPublicExponent();
      BigInteger n = publicKey.getModulus();

      BigInteger ip = this.p.getBigInteger(InsecureSecretKeyAccess.get());
      BigInteger iq = this.q.getBigInteger(InsecureSecretKeyAccess.get());
      BigInteger id = this.d.getBigInteger(InsecureSecretKeyAccess.get());
      BigInteger idP = this.dP.getBigInteger(InsecureSecretKeyAccess.get());
      BigInteger idQ = this.dQ.getBigInteger(InsecureSecretKeyAccess.get());
      BigInteger iqInv = this.qInv.getBigInteger(InsecureSecretKeyAccess.get());

      if (!ip.isProbablePrime(PRIME_CERTAINTY)) {
        throw new GeneralSecurityException("p is not a prime");
      }
      if (!iq.isProbablePrime(PRIME_CERTAINTY)) {
        throw new GeneralSecurityException("q is not a prime");
      }
      if (!ip.multiply(iq).equals(n)) {
        throw new GeneralSecurityException(
            "Prime p times prime q is not equal to the public key's modulus");
      }
      // lambda = LCM(p-1, q-1)
      BigInteger pMinusOne = ip.subtract(BigInteger.ONE);
      BigInteger qMinusOne = iq.subtract(BigInteger.ONE);
      BigInteger lambda = pMinusOne.divide(pMinusOne.gcd(qMinusOne)).multiply(qMinusOne);
      if (!e.multiply(id).mod(lambda).equals(BigInteger.ONE)) {
        throw new GeneralSecurityException("D is invalid.");
      }
      if (!e.multiply(idP).mod(pMinusOne).equals(BigInteger.ONE)) {
        throw new GeneralSecurityException("dP is invalid.");
      }
      if (!e.multiply(idQ).mod(qMinusOne).equals(BigInteger.ONE)) {
        throw new GeneralSecurityException("dQ is invalid.");
      }
      if (!iq.multiply(iqInv).mod(ip).equals(BigInteger.ONE)) {
        throw new GeneralSecurityException("qInv is invalid.");
      }
      return new RsaSsaPssPrivateKey(publicKey, p, q, d, dP, dQ, qInv);
    }
  }

  private RsaSsaPssPrivateKey(
      RsaSsaPssPublicKey publicKey,
      SecretBigInteger p,
      SecretBigInteger q,
      SecretBigInteger d,
      SecretBigInteger dP,
      SecretBigInteger dQ,
      SecretBigInteger qInv) {
    this.publicKey = publicKey;
    this.p = p;
    this.q = q;
    this.d = d;
    this.dP = dP;
    this.dQ = dQ;
    this.qInv = qInv;
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public static Builder builder() {
    return new Builder();
  }

  /** Returns the key parameters. */
  @Override
  public RsaSsaPssParameters getParameters() {
    return publicKey.getParameters();
  }

  /** Returns the public key. */
  @Override
  public RsaSsaPssPublicKey getPublicKey() {
    return publicKey;
  }

  /** Returns the prime factor p. */
  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public SecretBigInteger getPrimeP() {
    return p;
  }

  /** Returns the prime factor q. */
  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public SecretBigInteger getPrimeQ() {
    return q;
  }

  /** Returns the private exponent d. */
  public SecretBigInteger getPrivateExponent() {
    return d;
  }

  /** Returns the prime exponent dP. */
  public SecretBigInteger getPrimeExponentP() {
    return dP;
  }

  /** Returns the prime exponent dQ. */
  public SecretBigInteger getPrimeExponentQ() {
    return dQ;
  }

  /** Returns the CRT coefficient qInv. */
  public SecretBigInteger getCrtCoefficient() {
    return qInv;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof RsaSsaPssPrivateKey)) {
      return false;
    }
    RsaSsaPssPrivateKey that = (RsaSsaPssPrivateKey) o;
    return that.publicKey.equalsKey(publicKey)
        && p.equalsSecretBigInteger(that.p)
        && q.equalsSecretBigInteger(that.q)
        && d.equalsSecretBigInteger(that.d)
        && dP.equalsSecretBigInteger(that.dP)
        && dQ.equalsSecretBigInteger(that.dQ)
        && qInv.equalsSecretBigInteger(that.qInv);
  }
}
