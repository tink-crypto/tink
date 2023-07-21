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
public final class JwtRsaSsaPkcs1PrivateKeyTest {

  // Test vector from https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2
  static final BigInteger EXPONENT = new BigInteger(1, Base64.urlSafeDecode("AQAB"));
  static final BigInteger MODULUS =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx"
                  + "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs"
                  + "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH"
                  + "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV"
                  + "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8"
                  + "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"));
  static final BigInteger P =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi"
                  + "YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG"
                  + "BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc"));
  static final BigInteger Q =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa"
                  + "ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA"
                  + "-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"));
  static final BigInteger D =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I"
                  + "jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0"
                  + "BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn"
                  + "439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT"
                  + "CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh"
                  + "BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"));
  static final BigInteger DP =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q"
                  + "CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb"
                  + "34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0"));
  static final BigInteger DQ =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa"
                  + "7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky"
                  + "NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU"));
  static final BigInteger Q_INV =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o"
                  + "y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU"
                  + "W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"));

  @Test
  public void build_kidStrategyIgnored_hasExpectedValues() throws Exception {
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();
    JwtRsaSsaPkcs1PublicKey publicKey =
        JwtRsaSsaPkcs1PublicKey.builder().setParameters(parameters).setModulus(MODULUS).build();
    JwtRsaSsaPkcs1PrivateKey privateKey =
        JwtRsaSsaPkcs1PrivateKey.builder()
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
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.CUSTOM)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();
    JwtRsaSsaPkcs1PublicKey publicKey =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(parameters)
            .setModulus(MODULUS)
            .setCustomKid("customKid777")
            .build();
    JwtRsaSsaPkcs1PrivateKey privateKey =
        JwtRsaSsaPkcs1PrivateKey.builder()
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
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();
    JwtRsaSsaPkcs1PublicKey publicKey =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(parameters)
            .setModulus(MODULUS)
            .setIdRequirement(0x1ac6a944)
            .build();
    JwtRsaSsaPkcs1PrivateKey privateKey =
        JwtRsaSsaPkcs1PrivateKey.builder()
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
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();
    JwtRsaSsaPkcs1PublicKey publicKey =
        JwtRsaSsaPkcs1PublicKey.builder().setParameters(parameters).setModulus(MODULUS).build();

    // no public key
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtRsaSsaPkcs1PrivateKey.builder()
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
            JwtRsaSsaPkcs1PrivateKey.builder()
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
            JwtRsaSsaPkcs1PrivateKey.builder()
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
            JwtRsaSsaPkcs1PrivateKey.builder()
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
            JwtRsaSsaPkcs1PrivateKey.builder()
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
    assertThrows(GeneralSecurityException.class, () -> JwtRsaSsaPkcs1PrivateKey.builder().build());
  }

  @Test
  public void build_validatesValues() throws Exception {
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();
    // Check that build fails if any value is increased by 1.
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtRsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(
                    JwtRsaSsaPkcs1PublicKey.builder()
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
            JwtRsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(
                    JwtRsaSsaPkcs1PublicKey.builder()
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
            JwtRsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(
                    JwtRsaSsaPkcs1PublicKey.builder()
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
            JwtRsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(
                    JwtRsaSsaPkcs1PublicKey.builder()
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
            JwtRsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(
                    JwtRsaSsaPkcs1PublicKey.builder()
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
            JwtRsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(
                    JwtRsaSsaPkcs1PublicKey.builder()
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
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();
    JwtRsaSsaPkcs1PublicKey kidStrategyIgnoredPublicKey =
        JwtRsaSsaPkcs1PublicKey.builder().setParameters(parameters).setModulus(MODULUS).build();

    JwtRsaSsaPkcs1PublicKey kidStrategyBase64PublicKey =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(
                JwtRsaSsaPkcs1Parameters.builder()
                    .setModulusSizeBits(2048)
                    .setPublicExponent(EXPONENT)
                    .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                    .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
                    .build())
            .setModulus(MODULUS)
            .setIdRequirement(1907)
            .build();

    JwtRsaSsaPkcs1PublicKey kidStrategyIgnoredPublicKeyRS512 =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(
                JwtRsaSsaPkcs1Parameters.builder()
                    .setModulusSizeBits(2048)
                    .setPublicExponent(EXPONENT)
                    .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
                    .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS512)
                    .build())
            .setModulus(MODULUS)
            .build();

    JwtRsaSsaPkcs1Parameters parametersCustomKid =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.CUSTOM)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();
    JwtRsaSsaPkcs1PublicKey publicKeyCustomKid1 =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(parametersCustomKid)
            .setModulus(MODULUS)
            .setCustomKid("CustomKID1")
            .build();
    JwtRsaSsaPkcs1PublicKey publicKeyCustomKid2 =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(parametersCustomKid)
            .setModulus(MODULUS)
            .setCustomKid("CustomKID2")
            .build();

    new KeyTester()
        .addEqualityGroup(
            "kidStrategyIgnored",
            JwtRsaSsaPkcs1PrivateKey.builder()
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
            JwtRsaSsaPkcs1PrivateKey.builder()
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
            JwtRsaSsaPkcs1PrivateKey.builder()
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
            "KID ignored, RRS512",
            JwtRsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(kidStrategyIgnoredPublicKeyRS512)
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
            JwtRsaSsaPkcs1PrivateKey.builder()
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
            JwtRsaSsaPkcs1PrivateKey.builder()
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
            JwtRsaSsaPkcs1PrivateKey.builder()
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
