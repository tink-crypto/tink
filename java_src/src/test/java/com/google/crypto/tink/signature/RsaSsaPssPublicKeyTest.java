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
public final class RsaSsaPssPublicKeyTest {

  // Test vector from
  // https://github.com/google/wycheproof/blob/master/testvectors/rsa_pss_2048_sha256_mgf1_32_test.json
  static final BigInteger MODULUS =
      new BigInteger(
          "00a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e637f9746d3f7cafd31878d8"
              + "0325b6ef5a1700f65903b469429e89d6eac8845097b5ab393189db92512ed8a7711a1253facd20f79c"
              + "15e8247f3d3e42e46e48c98e254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed812996"
              + "15d9814c22da610428e09c7d9658594266f5c021d0fceca08d945a12be82de4d1ece6b4c03145b5d34"
              + "95d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a1969816f48698bcbba1b4d9cae79d460"
              + "d8f9f85e7975005d9bc22c4e5ac0f7c1a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9c"
              + "f7820283f742b9d5",
          16);
  static final BigInteger EXPONENT = BigInteger.valueOf(65537);

  @Test
  public void buildNoPrefixVariantAndGetProperties() throws Exception {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    assertThat(parameters.hasIdRequirement()).isFalse();
    RsaSsaPssPublicKey key =
        RsaSsaPssPublicKey.builder().setParameters(parameters).setModulus(MODULUS).build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getModulus()).isEqualTo(MODULUS);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void buildTinkVariantAndGetProperties() throws Exception {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.TINK)
            .setSaltLengthBytes(32)
            .build();
    assertThat(parameters.hasIdRequirement()).isTrue();
    RsaSsaPssPublicKey key =
        RsaSsaPssPublicKey.builder()
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
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.LEGACY)
            .setSaltLengthBytes(32)
            .build();
    assertThat(parameters.hasIdRequirement()).isTrue();
    RsaSsaPssPublicKey key =
        RsaSsaPssPublicKey.builder()
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
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.CRUNCHY)
            .setSaltLengthBytes(32)
            .build();
    assertThat(parameters.hasIdRequirement()).isTrue();
    RsaSsaPssPublicKey key =
        RsaSsaPssPublicKey.builder()
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
    assertThrows(GeneralSecurityException.class, () -> RsaSsaPssPublicKey.builder().build());
  }

  @Test
  public void buildWithoutParameters_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> RsaSsaPssPublicKey.builder().setModulus(MODULUS).build());
  }

  @Test
  public void buildWithoutPublicPoint_fails() throws Exception {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> RsaSsaPssPublicKey.builder().setParameters(parameters).build());
  }

  @Test
  public void parametersRequireIdButIdIsNotSetInBuild_fails() throws Exception {
    RsaSsaPssParameters parametersWithIdRequirement =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.TINK)
            .setSaltLengthBytes(32)
            .build();
    assertThat(parametersWithIdRequirement.hasIdRequirement()).isTrue();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPssPublicKey.builder()
                .setParameters(parametersWithIdRequirement)
                .setModulus(MODULUS)
                .build());
  }

  @Test
  public void parametersDoesNotRequireIdButIdIsSetInBuild_fails() throws Exception {
    RsaSsaPssParameters parametersWithoutIdRequirement =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    assertThat(parametersWithoutIdRequirement.hasIdRequirement()).isFalse();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RsaSsaPssPublicKey.builder()
                .setParameters(parametersWithoutIdRequirement)
                .setModulus(MODULUS)
                .setIdRequirement(0x66AABBCC)
                .build());
  }

  @Test
  public void modulusSizeIsValidated() throws Exception {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(3456)
            .setPublicExponent(EXPONENT)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    // Modulus between 2^3455 and 2^3456 are valid.
    BigInteger tooSmall = BigInteger.valueOf(2).pow(3455).subtract(BigInteger.ONE);
    BigInteger smallest = BigInteger.valueOf(2).pow(3455).add(BigInteger.ONE);
    BigInteger biggest = BigInteger.valueOf(2).pow(3456).subtract(BigInteger.ONE);
    BigInteger tooBig = BigInteger.valueOf(2).pow(3456).add(BigInteger.ONE);
    assertThrows(
        GeneralSecurityException.class,
        () -> RsaSsaPssPublicKey.builder().setParameters(parameters).setModulus(tooSmall).build());
    RsaSsaPssPublicKey publicKeyWithSmallestModulus =
        RsaSsaPssPublicKey.builder().setParameters(parameters).setModulus(smallest).build();
    assertThat(publicKeyWithSmallestModulus.getModulus()).isEqualTo(smallest);
    RsaSsaPssPublicKey publicKeyWithBiggestModulus =
        RsaSsaPssPublicKey.builder().setParameters(parameters).setModulus(biggest).build();
    assertThat(publicKeyWithBiggestModulus.getModulus()).isEqualTo(biggest);
    assertThrows(
        GeneralSecurityException.class,
        () -> RsaSsaPssPublicKey.builder().setParameters(parameters).setModulus(tooBig).build());
  }

  @Test
  public void testEqualities() throws Exception {
    RsaSsaPssParameters noPrefixParameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    RsaSsaPssParameters noPrefixParametersCopy =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    RsaSsaPssParameters tinkPrefixParameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.TINK)
            .setSaltLengthBytes(32)
            .build();
    RsaSsaPssParameters legacyPrefixParameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.LEGACY)
            .setSaltLengthBytes(32)
            .build();
    RsaSsaPssParameters crunchyPrefixParameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.CRUNCHY)
            .setSaltLengthBytes(32)
            .build();
    RsaSsaPssParameters noPrefixParametersExponent65539 =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(BigInteger.valueOf(65539))
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    RsaSsaPssParameters noPrefixParametersSha512 =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA512)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA512)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    new KeyTester()
        .addEqualityGroup(
            "No prefix, P256",
            RsaSsaPssPublicKey.builder()
                .setParameters(noPrefixParameters)
                .setModulus(MODULUS)
                .build(),
            // the same key built twice must be equal
            RsaSsaPssPublicKey.builder()
                .setParameters(noPrefixParametersCopy)
                .setModulus(MODULUS)
                .build(),
            // setting id requirement to null is equal to not setting it
            RsaSsaPssPublicKey.builder()
                .setParameters(noPrefixParameters)
                .setModulus(MODULUS)
                .setIdRequirement(null)
                .build())
        // This group checks that keys with different key bytes are not equal
        .addEqualityGroup(
            "No prefix, different modulus",
            RsaSsaPssPublicKey.builder()
                .setParameters(noPrefixParameters)
                .setModulus(MODULUS.add(BigInteger.ONE))
                .build())
        // These groups checks that keys with different parameters are not equal
        .addEqualityGroup(
            "No prefix, e=65539",
            RsaSsaPssPublicKey.builder()
                .setParameters(noPrefixParametersExponent65539)
                .setModulus(MODULUS)
                .build())
        .addEqualityGroup(
            "No prefix, SHA512",
            RsaSsaPssPublicKey.builder()
                .setParameters(noPrefixParametersSha512)
                .setModulus(MODULUS)
                .build())
        .addEqualityGroup(
            "Tink with key id 1907",
            RsaSsaPssPublicKey.builder()
                .setParameters(tinkPrefixParameters)
                .setModulus(MODULUS)
                .setIdRequirement(1907)
                .build())
        // This group checks that keys with different key ids are not equal
        .addEqualityGroup(
            "Tink with key id 1908",
            RsaSsaPssPublicKey.builder()
                .setParameters(tinkPrefixParameters)
                .setModulus(MODULUS)
                .setIdRequirement(1908)
                .build())
        // These 2 groups check that keys with different output prefix types are not equal
        .addEqualityGroup(
            "Legacy with key id 1907",
            RsaSsaPssPublicKey.builder()
                .setParameters(legacyPrefixParameters)
                .setModulus(MODULUS)
                .setIdRequirement(1907)
                .build())
        .addEqualityGroup(
            "Crunchy with key id 1907",
            RsaSsaPssPublicKey.builder()
                .setParameters(crunchyPrefixParameters)
                .setModulus(MODULUS)
                .setIdRequirement(1907)
                .build())
        .doTests();
  }
}
