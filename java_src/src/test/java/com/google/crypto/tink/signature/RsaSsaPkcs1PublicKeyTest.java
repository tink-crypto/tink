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

import com.google.crypto.tink.internal.KeyTester;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class RsaSsaPkcs1PublicKeyTest {

  // Test vector from
  // https://github.com/google/wycheproof/blob/master/testvectors/rsa_pkcs1_2048_test.json
  static final BigInteger MODULUS =
      new BigInteger(
          "00b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808bc3df3e628d2792e51aad5c1"
              + "24b43bda453dca5cde4bcf28e7bd4effba0cb4b742bbb6d5a013cb63d1aa3a89e02627ef5398b52c0c"
              + "fd97d208abeb8d7c9bce0bbeb019a86ddb589beb29a5b74bf861075c677c81d430f030c265247af9d3"
              + "c9140ccb65309d07e0adc1efd15cf17e7b055d7da3868e4648cc3a180f0ee7f8e1e7b18098a3391b4c"
              + "e7161e98d57af8a947e201a463e2d6bbca8059e5706e9dfed8f4856465ffa712ed1aa18e888d12dc6a"
              + "a09ce95ecfca83cc5b0b15db09c8647f5d524c0f2e7620a3416b9623cadc0f097af573261c98c8400a"
              + "a12af38e43cad84d",
          16);
  static final BigInteger EXPONENT = BigInteger.valueOf(65537);

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
    RsaSsaPkcs1PublicKey key =
        RsaSsaPkcs1PublicKey.builder().setParameters(parameters).setModulus(MODULUS).build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getModulus()).isEqualTo(MODULUS);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(key.getIdRequirementOrNull()).isNull();
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
    RsaSsaPkcs1PublicKey key =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(parameters)
            .setModulus(MODULUS)
            .setIdRequirement(0x66AABBCC)
            .build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getModulus()).isEqualTo(MODULUS);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0166AABBCC")));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
  }

  @Test
  public void buildLegacyVariantAndGetProperties() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.LEGACY)
            .build();
    assertThat(parameters.hasIdRequirement()).isTrue();
    RsaSsaPkcs1PublicKey key =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(parameters)
            .setModulus(MODULUS)
            .setIdRequirement(0x66AABBCC)
            .build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getModulus()).isEqualTo(MODULUS);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0066AABBCC")));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
  }

  @Test
  public void buildCrunchyVariantAndGetProperties() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.CRUNCHY)
            .build();
    assertThat(parameters.hasIdRequirement()).isTrue();
    RsaSsaPkcs1PublicKey key =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(parameters)
            .setModulus(MODULUS)
            .setIdRequirement(0x66AABBCC)
            .build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getModulus()).isEqualTo(MODULUS);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0066AABBCC")));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
  }

  @Test
  public void emptyBuild_fails() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> RsaSsaPkcs1PublicKey.builder().build());
  }

  @Test
  public void buildWithoutParameters_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> RsaSsaPkcs1PublicKey.builder().setModulus(MODULUS).build());
  }

  @Test
  public void buildWithoutPublicPoint_fails() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> RsaSsaPkcs1PublicKey.builder().setParameters(parameters).build());
  }

  @Test
  public void parametersRequireIdButIdIsNotSetInBuild_fails() throws Exception {
    RsaSsaPkcs1Parameters parametersWithIdRequirement =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.TINK)
            .build();
    assertThat(parametersWithIdRequirement.hasIdRequirement()).isTrue();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPkcs1PublicKey.builder()
                .setParameters(parametersWithIdRequirement)
                .setModulus(MODULUS)
                .build());
  }

  @Test
  public void parametersDoesNotRequireIdButIdIsSetInBuild_fails() throws Exception {
    RsaSsaPkcs1Parameters parametersWithoutIdRequirement =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    assertThat(parametersWithoutIdRequirement.hasIdRequirement()).isFalse();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPkcs1PublicKey.builder()
                .setParameters(parametersWithoutIdRequirement)
                .setModulus(MODULUS)
                .setIdRequirement(0x66AABBCC)
                .build());
  }

  @Test
  public void modulusSizeIsValidated() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(3456)
            .setPublicExponent(EXPONENT)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    // Modulus between 2^3455 and 2^3456 are valid.
    BigInteger tooSmall = BigInteger.valueOf(2).pow(3455).subtract(BigInteger.ONE);
    BigInteger smallest = BigInteger.valueOf(2).pow(3455).add(BigInteger.ONE);
    BigInteger biggest = BigInteger.valueOf(2).pow(3456).subtract(BigInteger.ONE);
    BigInteger tooBig = BigInteger.valueOf(2).pow(3456).add(BigInteger.ONE);
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPkcs1PublicKey.builder().setParameters(parameters).setModulus(tooSmall).build());
    RsaSsaPkcs1PublicKey publicKeyWithSmallestModulus =
        RsaSsaPkcs1PublicKey.builder().setParameters(parameters).setModulus(smallest).build();
    assertThat(publicKeyWithSmallestModulus.getModulus()).isEqualTo(smallest);
    RsaSsaPkcs1PublicKey publicKeyWithBiggestModulus =
        RsaSsaPkcs1PublicKey.builder().setParameters(parameters).setModulus(biggest).build();
    assertThat(publicKeyWithBiggestModulus.getModulus()).isEqualTo(biggest);
    assertThrows(
        GeneralSecurityException.class,
        () -> RsaSsaPkcs1PublicKey.builder().setParameters(parameters).setModulus(tooBig).build());
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
    RsaSsaPkcs1Parameters noPrefixParametersCopy =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1Parameters tinkPrefixParameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.TINK)
            .build();
    RsaSsaPkcs1Parameters legacyPrefixParameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.LEGACY)
            .build();
    RsaSsaPkcs1Parameters crunchyPrefixParameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.CRUNCHY)
            .build();
    RsaSsaPkcs1Parameters noPrefixParametersExponent65539 =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(BigInteger.valueOf(65539))
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1Parameters noPrefixParametersSha512 =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA512)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    new KeyTester()
        .addEqualityGroup(
            "No prefix, P256",
            RsaSsaPkcs1PublicKey.builder()
                .setParameters(noPrefixParameters)
                .setModulus(MODULUS)
                .build(),
            // the same key built twice must be equal
            RsaSsaPkcs1PublicKey.builder()
                .setParameters(noPrefixParametersCopy)
                .setModulus(MODULUS)
                .build(),
            // setting id requirement to null is equal to not setting it
            RsaSsaPkcs1PublicKey.builder()
                .setParameters(noPrefixParameters)
                .setModulus(MODULUS)
                .setIdRequirement(null)
                .build())
        // This group checks that keys with different key bytes are not equal
        .addEqualityGroup(
            "No prefix, different modulus",
            RsaSsaPkcs1PublicKey.builder()
                .setParameters(noPrefixParameters)
                .setModulus(MODULUS.add(BigInteger.ONE))
                .build())
        // These groups checks that keys with different parameters are not equal
        .addEqualityGroup(
            "No prefix, e=65539",
            RsaSsaPkcs1PublicKey.builder()
                .setParameters(noPrefixParametersExponent65539)
                .setModulus(MODULUS)
                .build())
        .addEqualityGroup(
            "No prefix, SHA512",
            RsaSsaPkcs1PublicKey.builder()
                .setParameters(noPrefixParametersSha512)
                .setModulus(MODULUS)
                .build())
        .addEqualityGroup(
            "Tink with key id 1907",
            RsaSsaPkcs1PublicKey.builder()
                .setParameters(tinkPrefixParameters)
                .setModulus(MODULUS)
                .setIdRequirement(1907)
                .build(),
            RsaSsaPkcs1PublicKey.builder()
                .setParameters(tinkPrefixParameters)
                .setModulus(MODULUS)
                .setIdRequirement(1907)
                .build())
        // This group checks that keys with different key ids are not equal
        .addEqualityGroup(
            "Tink with key id 1908",
            RsaSsaPkcs1PublicKey.builder()
                .setParameters(tinkPrefixParameters)
                .setModulus(MODULUS)
                .setIdRequirement(1908)
                .build())
        // These 2 groups check that keys with different output prefix types are not equal
        .addEqualityGroup(
            "Legacy with key id 1907",
            RsaSsaPkcs1PublicKey.builder()
                .setParameters(legacyPrefixParameters)
                .setModulus(MODULUS)
                .setIdRequirement(1907)
                .build())
        .addEqualityGroup(
            "Crunchy with key id 1907",
            RsaSsaPkcs1PublicKey.builder()
                .setParameters(crunchyPrefixParameters)
                .setModulus(MODULUS)
                .setIdRequirement(1907)
                .build())
        .doTests();
  }
}
