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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.internal.KeyTester;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.crypto.tink.util.SecretBytes;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class RsaSsaPkcs1PrivateKeyTest {

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
  public void buildNoPrefixVariantAndGetProperties() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters.hasIdRequirement()).isFalse();
    RsaSsaPkcs1PublicKey publicKey =
        RsaSsaPkcs1PublicKey.builder().setParameters(parameters).setModulus(MODULUS).build();
    RsaSsaPkcs1PrivateKey privateKey =
        RsaSsaPkcs1PrivateKey.builder()
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
    assertThat(privateKey.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(privateKey.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void buildTinkVariantAndGetProperties() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.TINK)
            .build();
    assertThat(parameters.hasIdRequirement()).isTrue();
    RsaSsaPkcs1PublicKey publicKey =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(parameters)
            .setModulus(MODULUS)
            .setIdRequirement(0x66AABBCC)
            .build();
    RsaSsaPkcs1PrivateKey privateKey =
        RsaSsaPkcs1PrivateKey.builder()
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
    assertThat(privateKey.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0166AABBCC")));
    assertThat(privateKey.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
  }

  @Test
  public void notAllValuesSet_throws() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1PublicKey publicKey =
        RsaSsaPkcs1PublicKey.builder().setParameters(parameters).setModulus(MODULUS).build();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPkcs1PrivateKey.builder()
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
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(publicKey)
                .setPrivateExponent(
                    SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
                .setPrimeExponents(
                    SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
                .setCrtCoefficient(
                    SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPkcs1PrivateKey.builder()
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
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(publicKey)
                .setPrimes(
                    SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
                .setPrivateExponent(
                    SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
                .setCrtCoefficient(
                    SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPkcs1PrivateKey.builder()
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
  public void valuesSetToNull_throws() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1PublicKey publicKey =
        RsaSsaPkcs1PublicKey.builder().setParameters(parameters).setModulus(MODULUS).build();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(null)
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
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(publicKey)
                .setPrimes(SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()), null)
                .setPrivateExponent(
                    SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
                .setPrimeExponents(
                    SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
                .setCrtCoefficient(
                    SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(publicKey)
                .setPrimes(
                    SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
                .setPrivateExponent(null)
                .setPrimeExponents(
                    SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
                .setCrtCoefficient(
                    SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(publicKey)
                .setPrimes(
                    SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
                .setPrivateExponent(
                    SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
                .setPrimeExponents(
                    null, SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
                .setCrtCoefficient(
                    SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(publicKey)
                .setPrimes(
                    SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
                .setPrivateExponent(
                    SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
                .setPrimeExponents(
                    SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
                .setCrtCoefficient(null)
                .build());
  }

  @Test
  public void buildFrom2048BitPrivateKeyGeneratedOnAndroidPhone() throws Exception {
    // This key pairs was generated on an android phone.
    // It satisfies e * d = 1 mod LCM(p-1, q-1), but e * d != 1 mod (p-1)(q-1).
    BigInteger modulus =
        new BigInteger(
            "b3795dceabcbd81fc437fd1bef3f441fb3e795e0def5dcb6c84d1136f1f5c552bcb549fc925a0bd84fba5014565a46e89c1b0f198323ddd6c74931eef6551414651d224965e880136a1ef0f58145aa1d801cf9abe8afcd79d18b71e992a440dac72e020622d707e39ef02422b3b5b60eee19e39262bef2c83384370d5af82208c905341cf3445357ebed8534e5d09e7e3faab0029eb72c4d67b784023dc3853601f46d8a76640c0cb70e32a7e1a915f64418b9872f90639e07c9c58cb6da7138ec00edceb95871f25b6d58541df81a05c20336ecb03d68f118e758fc8399c5afa965de8b3e6e2cffe05368c0c2e8f8d7651bc0595c315ad5ffc5e9181226a5d5",
            16);
    BigInteger e = new BigInteger("65537", 10);
    BigInteger d =
        new BigInteger(
            "3221514782158521239046688407258406330028553231891834758638194651218489349712866325521438421714836367531316613927931498512071990193965798572643232627837201196644319517052327671563822639251731918047441576305607916660284178027387674162132050160094809919355636813793351064368082273962217034909172344404581974193241939373282144264114913662260588365672363893632683074989847367188654224412555194872230331733391324889200933302437700487142724975686901108577545454632839147323098141162449990768306604007013959695761622579370899486808808004842820432382650026507647986123784123174922931280866259315314620233905351359011687391313",
            10);
    BigInteger p =
        new BigInteger(
            "158774943353490113489753012135278111098541279368787638170427666092698662171983127156976037521575652098385551704113475827318417186165950163951987243985985522595184323477005539699476104661027759513072140468348507403972716866975866335912344241205454260491734974839813729609658331285715361068926273165265719385439",
            10);
    BigInteger q =
        new BigInteger(
            "142695718417290075651435513804876109623436685476916701891113040095977093917632889732962474426931910603260254832314306994757612331416172717945809235744856009131743301134864401372069413649983267047705657073804311818666915219978411279698814772814372316278090214109479349638211641740638165276131916195227128960331",
            10);
    BigInteger dp =
        new BigInteger(
            "54757332036492112014516953480958174268721943273163834138395198270094376648475863100263551887676471134286132102726288671270440594499638457751236945367826491626048737037509791541992445756573377184101446798993133105644007913505173122423833934109368405566843064243548986322802349874418093456823956331253120978221",
            10);
    BigInteger dq =
        new BigInteger(
            "4123864239778253555759629875435789731400416288406247362280362206719572392388981692085858775418603822002455447341246890276804213737312222527570116003185334716198816124470652855618955238309173562847773234932715360552895882122146435811061769377762503120843231541317940830596042685151421106138423322302824087933",
            10);
    BigInteger crt =
        new BigInteger(
            "43369284071361709125656993969231593842392884522437628906059039642593092160995429320609799019215633408868044592180219813214250943675517000006014828230986217788818608645218728222984926523616075543476651226972790298584420864753413872673062587182578776079528269917000933056174453680725934830997227408181738889955",
            10);
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(e)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1PublicKey publicKey =
        RsaSsaPkcs1PublicKey.builder().setParameters(parameters).setModulus(modulus).build();

    RsaSsaPkcs1PrivateKey privateKey =
        RsaSsaPkcs1PrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrimes(
                SecretBigInteger.fromBigInteger(p, InsecureSecretKeyAccess.get()),
                SecretBigInteger.fromBigInteger(q, InsecureSecretKeyAccess.get()))
            .setPrivateExponent(SecretBigInteger.fromBigInteger(d, InsecureSecretKeyAccess.get()))
            .setPrimeExponents(
                SecretBigInteger.fromBigInteger(dp, InsecureSecretKeyAccess.get()),
                SecretBigInteger.fromBigInteger(dq, InsecureSecretKeyAccess.get()))
            .setCrtCoefficient(SecretBigInteger.fromBigInteger(crt, InsecureSecretKeyAccess.get()))
            .build();
    assertThat(privateKey).isNotNull();
  }

  @Test
  public void buildFromJavaRSAKeys() throws Exception {
    // Create a new RSA key pair using Java's KeyPairGenerator, which gives us a
    // RSAPublicKey and a RSAPrivateCrtKey.
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(2048, EXPONENT);
    keyGen.initialize(spec);
    KeyPair keyPair = keyGen.generateKeyPair();
    RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();

    // Build a RsaSsaPkcs1PublicKey from a RSAPublicKey.
    int pubKeyModulusSizeBits = pubKey.getModulus().bitLength();
    assertThat(pubKeyModulusSizeBits).isEqualTo(2048);
    RsaSsaPkcs1PublicKey publicKey =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(
                RsaSsaPkcs1Parameters.builder()
                    .setModulusSizeBits(pubKeyModulusSizeBits)
                    .setPublicExponent(pubKey.getPublicExponent())
                    .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
                    .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                    .build())
            .setModulus(pubKey.getModulus())
            .build();

    // Build a RsaSsaPkcs1PrivateKey from a RsaSsaPkcs1PublicKey and a RSAPrivateCrtKey.
    RsaSsaPkcs1PrivateKey privateKey =
        RsaSsaPkcs1PrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrimes(
                SecretBigInteger.fromBigInteger(privKey.getPrimeP(), InsecureSecretKeyAccess.get()),
                SecretBigInteger.fromBigInteger(privKey.getPrimeQ(), InsecureSecretKeyAccess.get()))
            .setPrivateExponent(
                SecretBigInteger.fromBigInteger(
                    privKey.getPrivateExponent(), InsecureSecretKeyAccess.get()))
            .setPrimeExponents(
                SecretBigInteger.fromBigInteger(
                    privKey.getPrimeExponentP(), InsecureSecretKeyAccess.get()),
                SecretBigInteger.fromBigInteger(
                    privKey.getPrimeExponentQ(), InsecureSecretKeyAccess.get()))
            .setCrtCoefficient(
                SecretBigInteger.fromBigInteger(
                    privKey.getCrtCoefficient(), InsecureSecretKeyAccess.get()))
            .build();

    // Build a RsaSsaPkcs1PrivateKey from a RSAPrivateCrtKey, without a RSAPublicKey.
    int privKeyModulusSizeBits = privKey.getModulus().bitLength();
    assertThat(privKeyModulusSizeBits).isEqualTo(2048);
    RsaSsaPkcs1PrivateKey privateKey2 =
        RsaSsaPkcs1PrivateKey.builder()
            .setPublicKey(
                RsaSsaPkcs1PublicKey.builder()
                    .setParameters(
                        RsaSsaPkcs1Parameters.builder()
                            .setModulusSizeBits(privKeyModulusSizeBits)
                            .setPublicExponent(privKey.getPublicExponent())
                            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
                            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                            .build())
                    .setModulus(privKey.getModulus())
                    .build())
            .setPrimes(
                SecretBigInteger.fromBigInteger(privKey.getPrimeP(), InsecureSecretKeyAccess.get()),
                SecretBigInteger.fromBigInteger(privKey.getPrimeQ(), InsecureSecretKeyAccess.get()))
            .setPrivateExponent(
                SecretBigInteger.fromBigInteger(
                    privKey.getPrivateExponent(), InsecureSecretKeyAccess.get()))
            .setPrimeExponents(
                SecretBigInteger.fromBigInteger(
                    privKey.getPrimeExponentP(), InsecureSecretKeyAccess.get()),
                SecretBigInteger.fromBigInteger(
                    privKey.getPrimeExponentQ(), InsecureSecretKeyAccess.get()))
            .setCrtCoefficient(
                SecretBigInteger.fromBigInteger(
                    privKey.getCrtCoefficient(), InsecureSecretKeyAccess.get()))
            .build();
    assertThat(privateKey.equalsKey(privateKey2)).isTrue();

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");

    // Convert RsaSsaPkcs1PublicKey back into a RSAPublicKey.
    RSAPublicKey pubKey2 =
        (RSAPublicKey)
            keyFactory.generatePublic(
                new RSAPublicKeySpec(
                    publicKey.getModulus(), publicKey.getParameters().getPublicExponent()));
    assertThat(pubKey2.getModulus()).isEqualTo(pubKey.getModulus());
    assertThat(pubKey2.getPublicExponent()).isEqualTo(pubKey.getPublicExponent());

    // Convert RsaSsaPkcs1PrivateKey back into a RSAPrivateCrtKey.
    BigInteger e = privateKey.getPublicKey().getParameters().getPublicExponent();
    BigInteger n = privateKey.getPublicKey().getModulus();
    BigInteger p = privateKey.getPrimeP().getBigInteger(InsecureSecretKeyAccess.get());
    BigInteger q = privateKey.getPrimeQ().getBigInteger(InsecureSecretKeyAccess.get());
    BigInteger d = privateKey.getPrivateExponent().getBigInteger(InsecureSecretKeyAccess.get());
    BigInteger dp = privateKey.getPrimeExponentP().getBigInteger(InsecureSecretKeyAccess.get());
    BigInteger dq = privateKey.getPrimeExponentQ().getBigInteger(InsecureSecretKeyAccess.get());
    BigInteger crt = privateKey.getCrtCoefficient().getBigInteger(InsecureSecretKeyAccess.get());
    RSAPrivateCrtKey privKey2 =
        (RSAPrivateCrtKey)
            keyFactory.generatePrivate(new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, crt));
    assertThat(privKey2.getPrivateExponent()).isEqualTo(privKey.getPrivateExponent());
    assertThat(privKey2.getPrimeExponentP()).isEqualTo(privKey.getPrimeExponentP());
    assertThat(privKey2.getPrimeExponentQ()).isEqualTo(privKey.getPrimeExponentQ());
    assertThat(privKey2.getCrtCoefficient()).isEqualTo(privKey.getCrtCoefficient());
  }

  @Test
  public void emptyBuild_fails() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> RsaSsaPkcs1PrivateKey.builder().build());
  }

  @Test
  public void buildWithoutPublicKey_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPkcs1PrivateKey.builder()
                .setPrimes(
                    SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
                .build());
  }

  @Test
  public void buildValidatesAllValues() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    // Check that build fails if any value is increased by 1.
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(
                    RsaSsaPkcs1PublicKey.builder()
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
            RsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(
                    RsaSsaPkcs1PublicKey.builder()
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
            RsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(
                    RsaSsaPkcs1PublicKey.builder()
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
            RsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(
                    RsaSsaPkcs1PublicKey.builder()
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
            RsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(
                    RsaSsaPkcs1PublicKey.builder()
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
            RsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(
                    RsaSsaPkcs1PublicKey.builder()
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
    RsaSsaPkcs1Parameters noPrefixParameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1PublicKey noPrefixPublicKey =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(noPrefixParameters)
            .setModulus(MODULUS)
            .build();

    RsaSsaPkcs1Parameters noPrefixParametersWithSha512 =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA512)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();

    RsaSsaPkcs1Parameters tinkPrefixParameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.TINK)
            .build();
    RsaSsaPkcs1PublicKey tinkPrefixPublicKey =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(tinkPrefixParameters)
            .setModulus(MODULUS)
            .setIdRequirement(1907)
            .build();

    // d2 = d + (p-1)(q-1) is also a valid d, yet if we change d to d2 the Key will be considered
    // different.
    BigInteger d2 = D.add(P.subtract(BigInteger.ONE).multiply(Q.subtract(BigInteger.ONE)));

    Ed25519PublicKey ed25519PublicKey =
        Ed25519PublicKey.create(
            Bytes.copyFrom(
                Hex.decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")));
    Ed25519PrivateKey ed25519PrivateKey =
        Ed25519PrivateKey.create(
            ed25519PublicKey,
            SecretBytes.copyFrom(
                Hex.decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
                InsecureSecretKeyAccess.get()));

    new KeyTester()
        .addEqualityGroup(
            "Unmodified",
            RsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(noPrefixPublicKey)
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
            RsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(
                    RsaSsaPkcs1PublicKey.builder()
                        .setParameters(
                            RsaSsaPkcs1Parameters.builder()
                                .setModulusSizeBits(2048)
                                .setPublicExponent(EXPONENT)
                                .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
                                .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                                .build())
                        .setModulus(MODULUS)
                        .build())
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
            RsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(noPrefixPublicKey)
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
        // Different d is considered a different key.
        .addEqualityGroup(
            "Different d",
            RsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(noPrefixPublicKey)
                .setPrimes(
                    SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
                .setPrivateExponent(
                    SecretBigInteger.fromBigInteger(d2, InsecureSecretKeyAccess.get()))
                .setPrimeExponents(
                    SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                    SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
                .setCrtCoefficient(
                    SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
                .build())
        // This group checks that keys with different parameters are not equal
        .addEqualityGroup(
            "SHA512",
            RsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(
                    RsaSsaPkcs1PublicKey.builder()
                        .setParameters(noPrefixParametersWithSha512)
                        .setModulus(MODULUS)
                        .build())
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
            "Tink Prefix",
            RsaSsaPkcs1PrivateKey.builder()
                .setPublicKey(tinkPrefixPublicKey)
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
        .addEqualityGroup("Other key type", ed25519PrivateKey)
        .doTests();
  }
}
