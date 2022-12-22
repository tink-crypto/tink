// Copyright 2022 Google LLC
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
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBigInteger;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class EcdsaPrivateKeyTest {

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
  public void buildNoPrefixVariantAndGetProperties() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters.hasIdRequirement()).isFalse();
    EcdsaPublicKey publicKey =
        EcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(P256_PUBLIC_POINT)
            .build();
    EcdsaPrivateKey privateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(
                SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()))
            .build();
    assertThat(privateKey.getParameters()).isEqualTo(parameters);
    assertThat(privateKey.getPublicKey()).isEqualTo(publicKey);
    assertThat(privateKey.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()))
        .isEqualTo(P256_PRIVATE_VALUE);
    assertThat(privateKey.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(privateKey.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void buildTinkVariantAndGetProperties() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.TINK)
            .build();
    assertThat(parameters.hasIdRequirement()).isTrue();
    EcdsaPublicKey publicKey =
        EcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(P256_PUBLIC_POINT)
            .setIdRequirement(0x66AABBCC)
            .build();
    EcdsaPrivateKey privateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(
                SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()))
            .build();
    assertThat(privateKey.getParameters()).isEqualTo(parameters);
    assertThat(privateKey.getPublicKey()).isEqualTo(publicKey);
    assertThat(privateKey.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()))
        .isEqualTo(P256_PRIVATE_VALUE);
    assertThat(privateKey.getOutputPrefix())
        .isEqualTo(Bytes.copyFrom(TestUtil.hexDecode("0166AABBCC")));
    assertThat(privateKey.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
  }

  @Test
  public void buildFromJavaECKeys() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(EcdsaParameters.CurveType.NIST_P384.toParameterSpec());
    KeyPair keyPair = keyGen.generateKeyPair();

    ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
    ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();

    // Check that the specs of ecPrivateKey and ecPublicKey are what we expect.
    assertThat(EcdsaParameters.CurveType.fromParameterSpec(ecPrivateKey.getParams()))
        .isEqualTo(EcdsaParameters.CurveType.NIST_P384);
    assertThat(EcdsaParameters.CurveType.fromParameterSpec(ecPublicKey.getParams()))
        .isEqualTo(EcdsaParameters.CurveType.NIST_P384);

    // Fill in the remaining parameters that match the curve type
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P384)
            .setHashType(EcdsaParameters.HashType.SHA384)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();

    // generate the EcdsaPrivateKey using ecPublicKey and ecPrivateKey
    EcdsaPublicKey publicKey =
        EcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(ecPublicKey.getW())
            .build();
    EcdsaPrivateKey privateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(
                SecretBigInteger.fromBigInteger(ecPrivateKey.getS(), InsecureSecretKeyAccess.get()))
            .build();

    // we skip testing any other properties of privateKey.
    assertThat(privateKey).isNotNull();
  }

  @Test
  public void emptyBuild_fails() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> EcdsaPublicKey.builder().build());
  }

  @Test
  public void buildWithoutPublicKey_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            EcdsaPrivateKey.builder()
                .setPrivateValue(
                    SecretBigInteger.fromBigInteger(
                        P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()))
                .build());
  }

  @Test
  public void build_validatesPrivateValue() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    EcdsaPublicKey publicKey =
        EcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(P256_PUBLIC_POINT)
            .build();
    EcdsaPrivateKey valid =
        EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(
                SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()))
            .build();
    assertThat(valid.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()))
        .isEqualTo(P256_PRIVATE_VALUE);
    BigInteger invalidPrivateValue = P256_PRIVATE_VALUE.add(BigInteger.ONE);
    assertThrows(
        GeneralSecurityException.class,
        () ->
            EcdsaPrivateKey.builder()
                .setPublicKey(publicKey)
                .setPrivateValue(
                    SecretBigInteger.fromBigInteger(
                        invalidPrivateValue, InsecureSecretKeyAccess.get()))
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            EcdsaPrivateKey.builder()
                .setPublicKey(publicKey)
                .setPrivateValue(
                    SecretBigInteger.fromBigInteger(BigInteger.ZERO, InsecureSecretKeyAccess.get()))
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            EcdsaPrivateKey.builder()
                .setPublicKey(publicKey)
                .setPrivateValue(
                    SecretBigInteger.fromBigInteger(
                        new BigInteger("-1"), InsecureSecretKeyAccess.get()))
                .build());
  }

  @Test
  public void build_rejectsPrivateValueThatIsLargerThanOrder() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    EcdsaPublicKey publicKey =
        EcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(P256_PUBLIC_POINT)
            .build();
    EcdsaPrivateKey valid =
        EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(
                SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()))
            .build();
    assertThat(valid.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()))
        .isEqualTo(P256_PRIVATE_VALUE);
    // Add the order of the generator to the private value.
    BigInteger tooLargePrivateValue =
        P256_PRIVATE_VALUE.add(EcdsaParameters.CurveType.NIST_P256.toParameterSpec().getOrder());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            EcdsaPrivateKey.builder()
                .setPublicKey(publicKey)
                .setPrivateValue(
                    SecretBigInteger.fromBigInteger(
                        tooLargePrivateValue, InsecureSecretKeyAccess.get()))
                .build());
  }

  @Test
  public void testEqualities() throws Exception {
    EcdsaPublicKey noPrefixPublicKey =
        EcdsaPublicKey.builder()
            .setParameters(
                EcdsaParameters.builder()
                    .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                    .setCurveType(EcdsaParameters.CurveType.NIST_P256)
                    .setHashType(EcdsaParameters.HashType.SHA256)
                    .setVariant(EcdsaParameters.Variant.NO_PREFIX)
                    .build())
            .setPublicPoint(P256_PUBLIC_POINT)
            .build();

    // Uses generator as public key, and private key as ONE
    EcdsaPublicKey noPrefixPublicKeyOne =
        EcdsaPublicKey.builder()
            .setParameters(
                EcdsaParameters.builder()
                    .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                    .setCurveType(EcdsaParameters.CurveType.NIST_P256)
                    .setHashType(EcdsaParameters.HashType.SHA256)
                    .setVariant(EcdsaParameters.Variant.NO_PREFIX)
                    .build())
            .setPublicPoint(EcdsaParameters.CurveType.NIST_P256.toParameterSpec().getGenerator())
            .build();

    EcdsaPublicKey tinkPrefixPublicKey =
        EcdsaPublicKey.builder()
            .setParameters(
                EcdsaParameters.builder()
                    .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                    .setCurveType(EcdsaParameters.CurveType.NIST_P256)
                    .setHashType(EcdsaParameters.HashType.SHA256)
                    .setVariant(EcdsaParameters.Variant.TINK)
                    .build())
            .setPublicPoint(P256_PUBLIC_POINT)
            .setIdRequirement(1907)
            .build();

    EcdsaPublicKey noPrefixPublicKeyP521 =
        EcdsaPublicKey.builder()
            .setParameters(
                EcdsaParameters.builder()
                    .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                    .setCurveType(EcdsaParameters.CurveType.NIST_P521)
                    .setHashType(EcdsaParameters.HashType.SHA512)
                    .setVariant(EcdsaParameters.Variant.NO_PREFIX)
                    .build())
            .setPublicPoint(P521_PUBLIC_POINT)
            .build();

    new KeyTester()
        .addEqualityGroup(
            "No prefix",
            EcdsaPrivateKey.builder()
                .setPublicKey(noPrefixPublicKey)
                .setPrivateValue(
                    SecretBigInteger.fromBigInteger(
                        P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()))
                .build(),
            // the same key built twice must be equal
            EcdsaPrivateKey.builder()
                .setPublicKey(noPrefixPublicKey)
                .setPrivateValue(
                    SecretBigInteger.fromBigInteger(
                        P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()))
                .build())
        // This group checks that keys with different key bytes are not equal
        .addEqualityGroup(
            "No prefix, ONE",
            EcdsaPrivateKey.builder()
                .setPublicKey(noPrefixPublicKeyOne)
                .setPrivateValue(
                    SecretBigInteger.fromBigInteger(BigInteger.ONE, InsecureSecretKeyAccess.get()))
                .build())
        // This group checks that keys with different parameters are not equal
        .addEqualityGroup(
            "No prefix, P521",
            EcdsaPrivateKey.builder()
                .setPublicKey(noPrefixPublicKeyP521)
                .setPrivateValue(
                    SecretBigInteger.fromBigInteger(
                        P521_PRIVATE_VALUE, InsecureSecretKeyAccess.get()))
                .build())
        .addEqualityGroup(
            "Tink with key id 1907",
            EcdsaPrivateKey.builder()
                .setPublicKey(tinkPrefixPublicKey)
                .setPrivateValue(
                    SecretBigInteger.fromBigInteger(
                        P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()))
                .build())
        .doTests();
  }
}
