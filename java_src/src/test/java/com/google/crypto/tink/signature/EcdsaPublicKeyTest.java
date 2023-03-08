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
import java.security.spec.ECPoint;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class EcdsaPublicKeyTest {

  private static final ECPoint A_P256_POINT =
      new ECPoint(
          new BigInteger("700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287", 16),
          new BigInteger("db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac", 16));

  private static final ECPoint INVALID_P256_POINT =
      new ECPoint(
          new BigInteger("700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287", 16),
          new BigInteger("db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ad", 16));

  private static final ECPoint A_P384_POINT =
      new ECPoint(
          new BigInteger(
              "a7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27fe7513272"
                  + "734466b400091adbf2d68c58e0c50066",
              16),
          new BigInteger(
              "ac68f19f2e1cb879aed43a9969b91a0839c4c38a49749b661efedf243451915e"
                  + "d0905a32b060992b468c64766fc8437a",
              16));

  private static final ECPoint A_P521_POINT =
        new ECPoint(
            new BigInteger(
                "000000685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a9490340"
                    + "854334b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2"
                    + "046d",
                16),
            new BigInteger(
                "000001ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b7398"
                    + "84a83bde99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302"
                    + "f676",
                16));

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
    EcdsaPublicKey key =
        EcdsaPublicKey.builder()
        .setParameters(parameters)
        .setPublicPoint(A_P256_POINT).build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getPublicPoint()).isEqualTo(A_P256_POINT);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(key.getIdRequirementOrNull()).isNull();
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
    EcdsaPublicKey key =
        EcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(A_P256_POINT)
            .setIdRequirement(0x66AABBCC)
            .build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getPublicPoint()).isEqualTo(A_P256_POINT);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0166AABBCC")));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
  }

  @Test
  public void buildLegacyVariantAndGetProperties() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.LEGACY)
            .build();
    assertThat(parameters.hasIdRequirement()).isTrue();
    EcdsaPublicKey key =
        EcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(A_P256_POINT)
            .setIdRequirement(0x66AABBCC)
            .build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getPublicPoint()).isEqualTo(A_P256_POINT);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0066AABBCC")));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
  }

  @Test
  public void buildCrunchyVariantAndGetProperties() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.CRUNCHY)
            .build();
    assertThat(parameters.hasIdRequirement()).isTrue();
    EcdsaPublicKey key =
        EcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(A_P256_POINT)
            .setIdRequirement(0x66AABBCC)
            .build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getPublicPoint()).isEqualTo(A_P256_POINT);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0066AABBCC")));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
  }

  @Test
  public void buildWithP384AndGetProperties() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P384)
            .setHashType(EcdsaParameters.HashType.SHA384)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    EcdsaPublicKey key =
        EcdsaPublicKey.builder().setParameters(parameters).setPublicPoint(A_P384_POINT).build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getPublicPoint()).isEqualTo(A_P384_POINT);
  }

  @Test
  public void buildWithP521AndGetProperties() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P521)
            .setHashType(EcdsaParameters.HashType.SHA512)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    EcdsaPublicKey key =
        EcdsaPublicKey.builder().setParameters(parameters).setPublicPoint(A_P521_POINT).build();
    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getPublicPoint()).isEqualTo(A_P521_POINT);
  }

  @Test
  public void emptyBuild_fails() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> EcdsaPublicKey.builder().build());
  }

  @Test
  public void buildWithoutParameters_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> EcdsaPublicKey.builder().setPublicPoint(A_P256_POINT).build());
  }

  @Test
  public void buildWithoutPublicPoint_fails() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> EcdsaPublicKey.builder().setParameters(parameters).build());
  }

  @Test
  public void parametersRequireIdButIdIsNotSetInBuild_fails() throws Exception {
    EcdsaParameters parametersWithIdRequirement =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.TINK)
            .build();
    assertThat(parametersWithIdRequirement.hasIdRequirement()).isTrue();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            EcdsaPublicKey.builder()
                .setParameters(parametersWithIdRequirement)
                .setPublicPoint(A_P256_POINT)
                .build());
  }

  @Test
  public void parametersDoesNotRequireIdButIdIsSetInBuild_fails() throws Exception {
    EcdsaParameters parametersWithoutIdRequirement =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    assertThat(parametersWithoutIdRequirement.hasIdRequirement()).isFalse();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            EcdsaPublicKey.builder()
                .setParameters(parametersWithoutIdRequirement)
                .setPublicPoint(A_P256_POINT)
                .setIdRequirement(0x66AABBCC)
                .build());
  }

  @Test
  public void build_publicPointNotOnCurve_fails() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            EcdsaPublicKey.builder()
                .setParameters(parameters)
                .setPublicPoint(INVALID_P256_POINT)
                .build());
  }

  @Test
  public void build_publicPointOnOtherCurve_fails() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            EcdsaPublicKey.builder()
                .setParameters(parameters)
                .setPublicPoint(A_P521_POINT)
                .build());
  }

  @Test
  public void testEqualities() throws Exception {
    ECPoint aP256PointCopy =
      new ECPoint(
          new BigInteger("700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287", 16),
          new BigInteger("db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac", 16));
    ECPoint anotherP256Point =
      new ECPoint(
          new BigInteger("809f04289c64348c01515eb03d5ce7ac1a8cb9498f5caa50197e58d43a86a7ae", 16),
          new BigInteger("b29d84e811197f25eba8f5194092cb6ff440e26d4421011372461f579271cda3", 16));

    EcdsaParameters noPrefixParameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    EcdsaParameters tinkPrefixParameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.TINK)
            .build();
    EcdsaParameters legacyPrefixParameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.LEGACY)
            .build();
    EcdsaParameters crunchyPrefixParameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.CRUNCHY)
            .build();
    EcdsaParameters noPrefixParametersDer =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    EcdsaParameters noPrefixParametersP521 =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P521)
            .setHashType(EcdsaParameters.HashType.SHA512)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    new KeyTester()
        .addEqualityGroup(
            "No prefix, P256",
            EcdsaPublicKey.builder()
                .setParameters(noPrefixParameters)
                .setPublicPoint(A_P256_POINT)
                .build(),
            // the same key built twice must be equal
            EcdsaPublicKey.builder()
                .setParameters(noPrefixParameters)
                .setPublicPoint(A_P256_POINT)
                .build(),
            // the same key built with a copy of key bytes must be equal
            EcdsaPublicKey.builder()
                .setParameters(noPrefixParameters)
                .setPublicPoint(aP256PointCopy)
                .build(),
            // setting id requirement to null is equal to not setting it
            EcdsaPublicKey.builder()
                .setParameters(noPrefixParameters)
                .setPublicPoint(A_P256_POINT)
                .setIdRequirement(null)
                .build())
        // This group checks that keys with different key bytes are not equal
        .addEqualityGroup(
            "No prefix, different P256 point",
            EcdsaPublicKey.builder()
                .setParameters(noPrefixParameters)
                .setPublicPoint(anotherP256Point)
                .build())
        // These groups checks that keys with different parameters are not equal
        .addEqualityGroup(
            "No prefix, P521",
            EcdsaPublicKey.builder()
                .setParameters(noPrefixParametersP521)
                .setPublicPoint(A_P521_POINT)
                .build())
        .addEqualityGroup(
            "No prefix, DER encoding, P256",
            EcdsaPublicKey.builder()
                .setParameters(noPrefixParametersDer)
                .setPublicPoint(A_P256_POINT)
                .build())
        .addEqualityGroup(
            "Tink with key id 1907, P256",
            EcdsaPublicKey.builder()
                .setParameters(tinkPrefixParameters)
                .setPublicPoint(A_P256_POINT)
                .setIdRequirement(1907)
                .build(),
            EcdsaPublicKey.builder()
                .setParameters(tinkPrefixParameters)
                .setPublicPoint(A_P256_POINT)
                .setIdRequirement(1907)
                .build(),
            EcdsaPublicKey.builder()
                .setParameters(tinkPrefixParameters)
                .setPublicPoint(aP256PointCopy)
                .setIdRequirement(1907)
                .build())
        // This group checks that keys with different key ids are not equal
        .addEqualityGroup(
            "Tink with key id 1908, P256",
            EcdsaPublicKey.builder()
                .setParameters(tinkPrefixParameters)
                .setPublicPoint(A_P256_POINT)
                .setIdRequirement(1908)
                .build())
        // These 2 groups check that keys with different output prefix types are not equal
        .addEqualityGroup(
            "Legacy with key id 1907, P256",
            EcdsaPublicKey.builder()
                .setParameters(legacyPrefixParameters)
                .setPublicPoint(A_P256_POINT)
                .setIdRequirement(1907)
                .build())
        .addEqualityGroup(
            "Crunchy with key id 1907, P256",
            EcdsaPublicKey.builder()
                .setParameters(crunchyPrefixParameters)
                .setPublicPoint(A_P256_POINT)
                .setIdRequirement(1907)
                .build())
        .doTests();
  }
}
