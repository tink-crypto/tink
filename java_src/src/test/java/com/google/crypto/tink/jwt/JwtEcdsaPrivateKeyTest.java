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
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.crypto.tink.util.SecretBytes;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import java.util.Optional;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class JwtEcdsaPrivateKeyTest {

  // Test case from https://www.ietf.org/rfc/rfc6979.txt, A.2.5
  private static final ECPoint P256_PUBLIC_POINT =
      new ECPoint(
          new BigInteger("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6", 16),
          new BigInteger("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299", 16));
  private static final BigInteger P256_PRIVATE_VALUE =
      new BigInteger("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16);

  // Test case from https://www.ietf.org/rfc/rfc6979.txt, A.2.5
  private static final ECPoint P521_PUBLIC_POINT =
      new ECPoint(
          new BigInteger(
              "1894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD3"
                  + "71123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F502"
                  + "3A4",
              16),
          new BigInteger(
              "0493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A2"
                  + "8A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDF"
                  + "CF5",
              16));
  private static final BigInteger P521_PRIVATE_VALUE =
      new BigInteger(
          "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C"
              + "AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83"
              + "538",
          16);

  @Test
  public void build_kidStrategyIgnored_getProperties_es256() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();
    JwtEcdsaPublicKey publicKey =
        JwtEcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(P256_PUBLIC_POINT)
            .build();
    JwtEcdsaPrivateKey privateKey =
        JwtEcdsaPrivateKey.create(
            publicKey,
            SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));
    assertThat(privateKey.getParameters()).isEqualTo(parameters);
    assertThat(privateKey.getPublicKey()).isEqualTo(publicKey);
    assertThat(privateKey.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()))
        .isEqualTo(P256_PRIVATE_VALUE);
    assertThat(privateKey.getKid()).isEqualTo(Optional.empty());
    assertThat(privateKey.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void build_kidStrategyIgnored_getProperties_es512() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
            .build();
    JwtEcdsaPublicKey publicKey =
        JwtEcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(P521_PUBLIC_POINT)
            .build();
    JwtEcdsaPrivateKey privateKey =
        JwtEcdsaPrivateKey.create(
            publicKey,
            SecretBigInteger.fromBigInteger(P521_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));
    assertThat(privateKey.getParameters()).isEqualTo(parameters);
    assertThat(privateKey.getPublicKey()).isEqualTo(publicKey);
    assertThat(privateKey.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()))
        .isEqualTo(P521_PRIVATE_VALUE);
    assertThat(privateKey.getKid()).isEqualTo(Optional.empty());
    assertThat(privateKey.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void build_kidStrategyCustom_getProperties_es256() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.CUSTOM)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();
    JwtEcdsaPublicKey publicKey =
        JwtEcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(P256_PUBLIC_POINT)
            .setCustomKid("Funny Custom KID")
            .build();
    JwtEcdsaPrivateKey privateKey =
        JwtEcdsaPrivateKey.create(
            publicKey,
            SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));
    assertThat(privateKey.getParameters()).isEqualTo(parameters);
    assertThat(privateKey.getPublicKey()).isEqualTo(publicKey);
    assertThat(privateKey.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()))
        .isEqualTo(P256_PRIVATE_VALUE);
    assertThat(privateKey.getKid()).isEqualTo(Optional.of("Funny Custom KID"));
    assertThat(privateKey.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void build_kidStrategyBase64_getProperties_es256() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();
    JwtEcdsaPublicKey publicKey =
        JwtEcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(P256_PUBLIC_POINT)
            .setIdRequirement(0x1ac6a944)
            .build();
    JwtEcdsaPrivateKey privateKey =
        JwtEcdsaPrivateKey.create(
            publicKey,
            SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));
    assertThat(privateKey.getParameters()).isEqualTo(parameters);
    assertThat(privateKey.getPublicKey()).isEqualTo(publicKey);
    assertThat(privateKey.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()))
        .isEqualTo(P256_PRIVATE_VALUE);
    // See JwtFormatTest.getKidFromTinkOutputPrefixType_success
    assertThat(privateKey.getKid()).isEqualTo(Optional.of("GsapRA"));
    assertThat(privateKey.getIdRequirementOrNull()).isEqualTo(0x1ac6a944);
  }

  @Test
  public void build_validatesPrivateValue() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();
    JwtEcdsaPublicKey publicKey =
        JwtEcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(P256_PUBLIC_POINT)
            .build();
    JwtEcdsaPrivateKey privateKey =
        JwtEcdsaPrivateKey.create(
            publicKey,
            SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

    assertThat(privateKey.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()))
        .isEqualTo(P256_PRIVATE_VALUE);

    // If we add 1 to the private key validation will fail.
    SecretBigInteger invalidPrivateValue =
        SecretBigInteger.fromBigInteger(
            P256_PRIVATE_VALUE.add(BigInteger.ONE), InsecureSecretKeyAccess.get());
    assertThrows(
        GeneralSecurityException.class,
        () -> JwtEcdsaPrivateKey.create(publicKey, invalidPrivateValue));
    // If we use 0 as private key validation will fail.
    SecretBigInteger zero =
        SecretBigInteger.fromBigInteger(BigInteger.ZERO, InsecureSecretKeyAccess.get());
    assertThrows(GeneralSecurityException.class, () -> JwtEcdsaPrivateKey.create(publicKey, zero));
    // If we use -1 as private key validation will fail.
    SecretBigInteger minusOne =
        SecretBigInteger.fromBigInteger(new BigInteger("-1"), InsecureSecretKeyAccess.get());
    assertThrows(
        GeneralSecurityException.class, () -> JwtEcdsaPrivateKey.create(publicKey, minusOne));
  }

  @Test
  public void build_rejectsPrivateValueThatIsLargerThanOrder() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();
    JwtEcdsaPublicKey publicKey =
        JwtEcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(P256_PUBLIC_POINT)
            .build();
    SecretBigInteger privateValuePlusOrder =
        SecretBigInteger.fromBigInteger(
            P256_PRIVATE_VALUE.add(
                JwtEcdsaParameters.Algorithm.ES256.getECParameterSpec().getOrder()),
            InsecureSecretKeyAccess.get());
    assertThrows(
        GeneralSecurityException.class,
        () -> JwtEcdsaPrivateKey.create(publicKey, privateValuePlusOrder));
    SecretBigInteger privateValueMinusOrder =
        SecretBigInteger.fromBigInteger(
            P256_PRIVATE_VALUE.subtract(
                JwtEcdsaParameters.Algorithm.ES256.getECParameterSpec().getOrder()),
            InsecureSecretKeyAccess.get());
    assertThrows(
        GeneralSecurityException.class,
        () -> JwtEcdsaPrivateKey.create(publicKey, privateValueMinusOrder));
  }

  @Test
  public void testEqualities() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();
    JwtEcdsaPublicKey kidStrategyIgnoredPublicKey =
        JwtEcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(P256_PUBLIC_POINT)
            .build();

    // Uses generator as public key, and private key as ONE
    JwtEcdsaPublicKey kidStrategyIgnoredPublicKeyForOne =
        JwtEcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(parameters.getAlgorithm().getECParameterSpec().getGenerator())
            .build();

    JwtEcdsaPublicKey kidStrategyBase64PublicKey =
        JwtEcdsaPublicKey.builder()
            .setParameters(
                JwtEcdsaParameters.builder()
                    .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                    .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
                    .build())
            .setPublicPoint(P256_PUBLIC_POINT)
            .setIdRequirement(1907)
            .build();

    JwtEcdsaPublicKey kidStrategyIgnoredPublicKeyES512 =
        JwtEcdsaPublicKey.builder()
            .setParameters(
                JwtEcdsaParameters.builder()
                    .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                    .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
                    .build())
            .setPublicPoint(P521_PUBLIC_POINT)
            .build();

    JwtEcdsaParameters parametersCustomKid =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.CUSTOM)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();
    JwtEcdsaPublicKey publicKeyCustomKid1 =
        JwtEcdsaPublicKey.builder()
            .setParameters(parametersCustomKid)
            .setPublicPoint(P256_PUBLIC_POINT)
            .setCustomKid("CustomKID1")
            .build();
    JwtEcdsaPublicKey publicKeyCustomKid2 =
        JwtEcdsaPublicKey.builder()
            .setParameters(parametersCustomKid)
            .setPublicPoint(P256_PUBLIC_POINT)
            .setCustomKid("CustomKID2")
            .build();

    new KeyTester()
        .addEqualityGroup(
            "kidStrategyIgnored",
            JwtEcdsaPrivateKey.create(
                kidStrategyIgnoredPublicKey,
                SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get())),
            // the same key built twice must be equal
            JwtEcdsaPrivateKey.create(
                kidStrategyIgnoredPublicKey,
                SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get())))
        // This group checks that keys with different key bytes are not equal
        .addEqualityGroup(
            "KID ignored, ONE",
            JwtEcdsaPrivateKey.create(
                kidStrategyIgnoredPublicKeyForOne,
                SecretBigInteger.fromBigInteger(BigInteger.ONE, InsecureSecretKeyAccess.get())))
        // This group checks that keys with different parameters are not equal
        .addEqualityGroup(
            "KID ignored, ES512",
            JwtEcdsaPrivateKey.create(
                kidStrategyIgnoredPublicKeyES512,
                SecretBigInteger.fromBigInteger(P521_PRIVATE_VALUE, InsecureSecretKeyAccess.get())))
        .addEqualityGroup(
            "KID Base 64",
            JwtEcdsaPrivateKey.create(
                kidStrategyBase64PublicKey,
                SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get())))
        .addEqualityGroup(
            "CustomKID1",
            JwtEcdsaPrivateKey.create(
                publicKeyCustomKid1,
                SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get())))
        .addEqualityGroup(
            "CustomKID2",
            JwtEcdsaPrivateKey.create(
                publicKeyCustomKid2,
                SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get())))
        .addEqualityGroup(
            "different key class",
            ChaCha20Poly1305Key.create(SecretBytes.randomBytes(32)))
        .doTests();
  }
}
