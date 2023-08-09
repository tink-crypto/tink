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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.aead.ChaCha20Poly1305Key;
import com.google.crypto.tink.internal.KeyTester;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.crypto.tink.util.SecretBytes;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Optional;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class JwtRsaSsaPssPrivateKeyTest {

  // Test vector from https://www.rfc-editor.org/rfc/rfc7517#appendix-C.1
  static final BigInteger EXPONENT = new BigInteger(1, Base64.urlSafeDecode("AQAB"));
  static final BigInteger MODULUS =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRy"
                  + "O125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP"
                  + "8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0"
                  + "Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0X"
                  + "OC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1"
                  + "_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q"));
  static final BigInteger P =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHf"
                  + "QP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8"
                  + "UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws"));
  static final BigInteger Q =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6I"
                  + "edis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYK"
                  + "rYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s"));
  static final BigInteger D =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfS"
                  + "NkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9U"
                  + "vqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnu"
                  + "ToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqADC6p1M3h33tsu"
                  + "rY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWmeRDkK2a"
                  + "hecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ"));
  static final BigInteger DP =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwKqvVDq3"
                  + "tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_lhqigI4y_kqS1w"
                  + "Y52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRViD6c"));
  static final BigInteger DQ =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9"
                  + "GQTB9yqpDoYaN06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBy"
                  + "mXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEAu_lRFCOJ3xDea-ots"));
  static final BigInteger Q_INV =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqq"
                  + "abu9V0-Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0o"
                  + "Yu_neotgQ0hzbI5gry7ajdYy9-2lNx_76aBZoOUu9HCJ-UsfSOI8"));

  @Test
  public void build_kidStrategyIgnored_hasExpectedValues() throws Exception {
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();
    JwtRsaSsaPssPublicKey publicKey =
        JwtRsaSsaPssPublicKey.builder().setParameters(parameters).setModulus(MODULUS).build();
    JwtRsaSsaPssPrivateKey privateKey =
        JwtRsaSsaPssPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrimes(
                SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
            .setPrivateExponent(SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
            .setPrimeExponents(
                SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
            .setCrtCoefficient(
                SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
            .build();
    assertThat(privateKey.getParameters()).isEqualTo(parameters);
    assertThat(privateKey.getPublicKey()).isEqualTo(publicKey);
    assertThat(privateKey.getPrimeP().getBigInteger(InsecureSecretKeyAccess.get())).isEqualTo(P);
    assertThat(privateKey.getPrimeQ().getBigInteger(InsecureSecretKeyAccess.get())).isEqualTo(Q);
    assertThat(privateKey.getPrimeExponentP().getBigInteger(InsecureSecretKeyAccess.get()))
        .isEqualTo(DP);
    assertThat(privateKey.getPrimeExponentQ().getBigInteger(InsecureSecretKeyAccess.get()))
        .isEqualTo(DQ);
    assertThat(privateKey.getCrtCoefficient().getBigInteger(InsecureSecretKeyAccess.get()))
        .isEqualTo(Q_INV);
    assertThat(privateKey.getPrivateExponent().getBigInteger(InsecureSecretKeyAccess.get()))
        .isEqualTo(D);

    assertThat(privateKey.getKid()).isEqualTo(Optional.empty());
    assertThat(privateKey.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void build_kidStrategyCustom_hasExpectedValues() throws Exception {
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.CUSTOM)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();
    JwtRsaSsaPssPublicKey publicKey =
        JwtRsaSsaPssPublicKey.builder()
            .setParameters(parameters)
            .setModulus(MODULUS)
            .setCustomKid("customKid777")
            .build();
    JwtRsaSsaPssPrivateKey privateKey =
        JwtRsaSsaPssPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrimes(
                SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
            .setPrivateExponent(SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
            .setPrimeExponents(
                SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
            .setCrtCoefficient(
                SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
            .build();
    assertThat(privateKey.getParameters()).isEqualTo(parameters);
    assertThat(privateKey.getPublicKey()).isEqualTo(publicKey);

    assertThat(privateKey.getKid().get()).isEqualTo("customKid777");
    assertThat(privateKey.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void build_kidStrategyBase64_hasExpectedValues() throws Exception {
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();
    JwtRsaSsaPssPublicKey publicKey =
        JwtRsaSsaPssPublicKey.builder()
            .setParameters(parameters)
            .setModulus(MODULUS)
            .setIdRequirement(0x1ac6a944)
            .build();
    JwtRsaSsaPssPrivateKey privateKey =
        JwtRsaSsaPssPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrimes(
                SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
            .setPrivateExponent(SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
            .setPrimeExponents(
                SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
            .setCrtCoefficient(
                SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
            .build();
    assertThat(privateKey.getParameters()).isEqualTo(parameters);
    assertThat(privateKey.getPublicKey()).isEqualTo(publicKey);

    assertThat(privateKey.getKid().get()).isEqualTo("GsapRA");
    assertThat(privateKey.getIdRequirementOrNull()).isEqualTo(0x1ac6a944);
  }

  @Test
  public void notAllValuesSet_throws() throws Exception {
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();
    JwtRsaSsaPssPublicKey publicKey =
        JwtRsaSsaPssPublicKey.builder().setParameters(parameters).setModulus(MODULUS).build();

    // no public key
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtRsaSsaPssPrivateKey.builder()
                .setPrimes(
                    SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
                .setPrivateExponent(
                    SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
                .setPrimeExponents(
                    SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
                .setCrtCoefficient(
                    SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
                .build());

    // no prime factors
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtRsaSsaPssPrivateKey.builder()
                .setPublicKey(publicKey)
                .setPrivateExponent(
                    SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
                .setPrimeExponents(
                    SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
                .setCrtCoefficient(
                    SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
                .build());

    // no private exponent
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtRsaSsaPssPrivateKey.builder()
                .setPublicKey(publicKey)
                .setPrimes(
                    SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
                .setPrimeExponents(
                    SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
                .setCrtCoefficient(
                    SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
                .build());

    // no factors crt exponents
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtRsaSsaPssPrivateKey.builder()
                .setPublicKey(publicKey)
                .setPrimes(
                    SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
                .setPrivateExponent(
                    SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
                .setCrtCoefficient(
                    SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
                .build());

    // no crt coefficient
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtRsaSsaPssPrivateKey.builder()
                .setPublicKey(publicKey)
                .setPrimes(
                    SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
                .setPrivateExponent(
                    SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
                .setPrimeExponents(
                    SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
                .build());
  }

  @Test
  public void emptyBuild_fails() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> JwtRsaSsaPssPrivateKey.builder().build());
  }

  @Test
  public void build_validatesValues() throws Exception {
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();
    // Check that build fails if any value is increased by 1.
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtRsaSsaPssPrivateKey.builder()
                .setPublicKey(
                    JwtRsaSsaPssPublicKey.builder()
                        .setParameters(parameters)
                        .setModulus(MODULUS.add(BigInteger.ONE)) // modulus is one off
                        .build())
                .setPrimes(
                    SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
                .setPrimeExponents(
                    SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
                .setCrtCoefficient(
                    SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtRsaSsaPssPrivateKey.builder()
                .setPublicKey(
                    JwtRsaSsaPssPublicKey.builder()
                        .setParameters(parameters)
                        .setModulus(MODULUS)
                        .build())
                .setPrimes(
                    SecretBigInteger.fromBigInteger(
                        P.add(BigInteger.ONE), InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
                .setPrimeExponents(
                    SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
                .setCrtCoefficient(
                    SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtRsaSsaPssPrivateKey.builder()
                .setPublicKey(
                    JwtRsaSsaPssPublicKey.builder()
                        .setParameters(parameters)
                        .setModulus(MODULUS)
                        .build())
                .setPrimes(
                    SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(
                        Q.add(BigInteger.ONE), InsecureSecretKeyAccess.get()))
                .setPrimeExponents(
                    SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
                .setCrtCoefficient(
                    SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtRsaSsaPssPrivateKey.builder()
                .setPublicKey(
                    JwtRsaSsaPssPublicKey.builder()
                        .setParameters(parameters)
                        .setModulus(MODULUS)
                        .build())
                .setPrimes(
                    SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
                .setPrimeExponents(
                    SecretBigInteger.fromBigInteger(
                        DP.add(BigInteger.ONE), InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
                .setCrtCoefficient(
                    SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtRsaSsaPssPrivateKey.builder()
                .setPublicKey(
                    JwtRsaSsaPssPublicKey.builder()
                        .setParameters(parameters)
                        .setModulus(MODULUS)
                        .build())
                .setPrimes(
                    SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
                .setPrimeExponents(
                    SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(
                        DQ.add(BigInteger.ONE), InsecureSecretKeyAccess.get()))
                .setCrtCoefficient(
                    SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtRsaSsaPssPrivateKey.builder()
                .setPublicKey(
                    JwtRsaSsaPssPublicKey.builder()
                        .setParameters(parameters)
                        .setModulus(MODULUS)
                        .build())
                .setPrimes(
                    SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
                .setPrimeExponents(
                    SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
                .setCrtCoefficient(
                    SecretBigInteger.fromBigInteger(
                        Q_INV.add(BigInteger.ONE), InsecureSecretKeyAccess.get()))
                .build());
  }

  @Test
  public void testEqualities() throws Exception {
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();
    JwtRsaSsaPssPublicKey kidStrategyIgnoredPublicKey =
        JwtRsaSsaPssPublicKey.builder().setParameters(parameters).setModulus(MODULUS).build();

    JwtRsaSsaPssPublicKey kidStrategyBase64PublicKey =
        JwtRsaSsaPssPublicKey.builder()
            .setParameters(
                JwtRsaSsaPssParameters.builder()
                    .setModulusSizeBits(2048)
                    .setPublicExponent(EXPONENT)
                    .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                    .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                    .build())
            .setModulus(MODULUS)
            .setIdRequirement(1907)
            .build();

    JwtRsaSsaPssPublicKey kidStrategyIgnoredPublicKeyPS512 =
        JwtRsaSsaPssPublicKey.builder()
            .setParameters(
                JwtRsaSsaPssParameters.builder()
                    .setModulusSizeBits(2048)
                    .setPublicExponent(EXPONENT)
                    .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                    .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS512)
                    .build())
            .setModulus(MODULUS)
            .build();

    JwtRsaSsaPssParameters parametersCustomKid =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.CUSTOM)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();
    JwtRsaSsaPssPublicKey publicKeyCustomKid1 =
        JwtRsaSsaPssPublicKey.builder()
            .setParameters(parametersCustomKid)
            .setModulus(MODULUS)
            .setCustomKid("CustomKID1")
            .build();
    JwtRsaSsaPssPublicKey publicKeyCustomKid2 =
        JwtRsaSsaPssPublicKey.builder()
            .setParameters(parametersCustomKid)
            .setModulus(MODULUS)
            .setCustomKid("CustomKID2")
            .build();

    new KeyTester()
        .addEqualityGroup(
            "kidStrategyIgnored",
            JwtRsaSsaPssPrivateKey.builder()
                .setPublicKey(kidStrategyIgnoredPublicKey)
                .setPrimes(
                    SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
                .setPrivateExponent(
                    SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
                .setPrimeExponents(
                    SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
                .setCrtCoefficient(
                    SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
                .build(),
            // the same key built twice must be equal
            JwtRsaSsaPssPrivateKey.builder()
                .setPublicKey(kidStrategyIgnoredPublicKey)
                .setPrimes(
                    SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
                .setPrivateExponent(
                    SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
                .setPrimeExponents(
                    SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
                .setCrtCoefficient(
                    SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
                .build())
        // This group checks that a private key where p and q are swapped is considered different
        .addEqualityGroup(
            "p and q swapped",
            JwtRsaSsaPssPrivateKey.builder()
                .setPublicKey(kidStrategyIgnoredPublicKey)
                .setPrimes(
                    SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()))
                .setPrivateExponent(
                    SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
                .setPrimeExponents(
                    SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()))
                .setCrtCoefficient(
                    SecretBigInteger.fromBigInteger(P.modInverse(Q), InsecureSecretKeyAccess.get()))
                .build())
        // This group checks that keys with different parameters are not equal
        .addEqualityGroup(
            "KID ignored, RPS512",
            JwtRsaSsaPssPrivateKey.builder()
                .setPublicKey(kidStrategyIgnoredPublicKeyPS512)
                .setPrimes(
                    SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
                .setPrivateExponent(
                    SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
                .setPrimeExponents(
                    SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
                .setCrtCoefficient(
                    SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
                .build())
        .addEqualityGroup(
            "KID Base 64",
            JwtRsaSsaPssPrivateKey.builder()
                .setPublicKey(kidStrategyBase64PublicKey)
                .setPrimes(
                    SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
                .setPrivateExponent(
                    SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
                .setPrimeExponents(
                    SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
                .setCrtCoefficient(
                    SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
                .build())
        .addEqualityGroup(
            "CustomKID1",
            JwtRsaSsaPssPrivateKey.builder()
                .setPublicKey(publicKeyCustomKid1)
                .setPrimes(
                    SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
                .setPrivateExponent(
                    SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
                .setPrimeExponents(
                    SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
                .setCrtCoefficient(
                    SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
                .build())
        .addEqualityGroup(
            "CustomKID2",
            JwtRsaSsaPssPrivateKey.builder()
                .setPublicKey(publicKeyCustomKid2)
                .setPrimes(
                    SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
                .setPrivateExponent(
                    SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
                .setPrimeExponents(
                    SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
                .setCrtCoefficient(
                    SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
                .build())
        .addEqualityGroup(
            "different key class", ChaCha20Poly1305Key.create(SecretBytes.randomBytes(32)))
        .doTests();
  }
}
