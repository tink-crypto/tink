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

package com.google.crypto.tink.jwt;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.RestrictedApi;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Optional;

/**
 * Represents a private key for RSA SSA PSS signatures (PS256, PS384, PS512).
 *
 * <p>Standard: https://datatracker.ietf.org/doc/html/rfc7518
 */
public final class JwtRsaSsaPssPrivateKey extends JwtSignaturePrivateKey {
  private final JwtRsaSsaPssPublicKey publicKey;
  private final SecretBigInteger d;
  private final SecretBigInteger p;
  private final SecretBigInteger q;
  private final SecretBigInteger dP;
  private final SecretBigInteger dQ;
  private final SecretBigInteger qInv;

  /** Builder for JwtRsaSsaPssPrivateKey. */
  public static class Builder {
    private Optional<JwtRsaSsaPssPublicKey> publicKey = Optional.empty();
    private Optional<SecretBigInteger> d = Optional.empty();
    private Optional<SecretBigInteger> p = Optional.empty();
    private Optional<SecretBigInteger> q = Optional.empty();
    private Optional<SecretBigInteger> dP = Optional.empty();
    private Optional<SecretBigInteger> dQ = Optional.empty();
    private Optional<SecretBigInteger> qInv = Optional.empty();

    private Builder() {}

    /**
     * Sets the public key, which includes the parameters.
     *
     * <p>This is required.
     */
    @CanIgnoreReturnValue
    public Builder setPublicKey(JwtRsaSsaPssPublicKey publicKey) {
      this.publicKey = Optional.of(publicKey);
      return this;
    }

    /**
     * Sets the prime factors p and q.
     *
     * <p>See https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.2.
     *
     * <p>This is required.
     */
    @CanIgnoreReturnValue
    public Builder setPrimes(SecretBigInteger p, SecretBigInteger q) {
      this.p = Optional.of(p);
      this.q = Optional.of(q);
      return this;
    }

    /**
     * Sets the private exponent d.
     *
     * <p>See https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.1.
     *
     * <p>This is required.
     */
    @CanIgnoreReturnValue
    public Builder setPrivateExponent(SecretBigInteger d) {
      this.d = Optional.of(d);
      return this;
    }

    /**
     * Sets the prime exponents dP and dQ.
     *
     * <p>See https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.4.
     *
     * <p>This is required.
     */
    @CanIgnoreReturnValue
    public Builder setPrimeExponents(SecretBigInteger dP, SecretBigInteger dQ) {
      this.dP = Optional.of(dP);
      this.dQ = Optional.of(dQ);
      return this;
    }

    /**
     * Sets the CRT coefficient qInv.
     *
     * <p>See https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.6.
     *
     * <p>This is required.
     */
    @CanIgnoreReturnValue
    public Builder setCrtCoefficient(SecretBigInteger qInv) {
      this.qInv = Optional.of(qInv);
      return this;
    }

    private static final int PRIME_CERTAINTY = 10;

    @AccessesPartialKey
    public JwtRsaSsaPssPrivateKey build() throws GeneralSecurityException {
      if (!publicKey.isPresent()) {
        throw new GeneralSecurityException("Cannot build without a RSA SSA PSS public key");
      }
      if (!p.isPresent() || !q.isPresent()) {
        throw new GeneralSecurityException("Cannot build without prime factors");
      }
      if (!d.isPresent()) {
        throw new GeneralSecurityException("Cannot build without private exponent");
      }
      if (!dP.isPresent() || !dQ.isPresent()) {
        throw new GeneralSecurityException("Cannot build without prime exponents");
      }
      if (!qInv.isPresent()) {
        throw new GeneralSecurityException("Cannot build without CRT coefficient");
      }
      BigInteger e = publicKey.get().getParameters().getPublicExponent();
      BigInteger n = publicKey.get().getModulus();

      BigInteger ip = this.p.get().getBigInteger(InsecureSecretKeyAccess.get());
      BigInteger iq = this.q.get().getBigInteger(InsecureSecretKeyAccess.get());
      BigInteger id = this.d.get().getBigInteger(InsecureSecretKeyAccess.get());
      BigInteger idP = this.dP.get().getBigInteger(InsecureSecretKeyAccess.get());
      BigInteger idQ = this.dQ.get().getBigInteger(InsecureSecretKeyAccess.get());
      BigInteger iqInv = this.qInv.get().getBigInteger(InsecureSecretKeyAccess.get());

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
      return new JwtRsaSsaPssPrivateKey(
          publicKey.get(), p.get(), q.get(), d.get(), dP.get(), dQ.get(), qInv.get());
    }
  }

  private JwtRsaSsaPssPrivateKey(
      JwtRsaSsaPssPublicKey publicKey,
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
  public JwtRsaSsaPssParameters getParameters() {
    return publicKey.getParameters();
  }

  /** Returns the public key. */
  @Override
  public JwtRsaSsaPssPublicKey getPublicKey() {
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
    if (!(o instanceof JwtRsaSsaPssPrivateKey)) {
      return false;
    }
    JwtRsaSsaPssPrivateKey that = (JwtRsaSsaPssPrivateKey) o;
    return that.publicKey.equalsKey(publicKey)
        && p.equalsSecretBigInteger(that.p)
        && q.equalsSecretBigInteger(that.q)
        && d.equalsSecretBigInteger(that.d)
        && dP.equalsSecretBigInteger(that.dP)
        && dQ.equalsSecretBigInteger(that.dQ)
        && qInv.equalsSecretBigInteger(that.qInv);
  }
}
