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

import com.google.crypto.tink.internal.EllipticCurvesUtil;
import com.google.crypto.tink.mac.HmacParameters;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class EcdsaParametersTest {

  @Test
  public void buildWithNoPrefixAndGetProperties() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters.getSignatureEncoding()).isEqualTo(EcdsaParameters.SignatureEncoding.IEEE_P1363);
    assertThat(parameters.getCurveType()).isEqualTo(EcdsaParameters.CurveType.NIST_P256);
    assertThat(parameters.getHashType()).isEqualTo(EcdsaParameters.HashType.SHA256);
    assertThat(parameters.getVariant()).isEqualTo(EcdsaParameters.Variant.NO_PREFIX);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void buildParametersWithoutSettingVariant_hasNoPrefix() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .build();
    assertThat(parameters.getVariant()).isEqualTo(EcdsaParameters.Variant.NO_PREFIX);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void buildParametersWithTinkPrefix() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.TINK)
            .build();
    assertThat(parameters.getVariant()).isEqualTo(EcdsaParameters.Variant.TINK);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void buildParametersWithLegacyPrefix() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.LEGACY)
            .build();
    assertThat(parameters.getVariant()).isEqualTo(EcdsaParameters.Variant.LEGACY);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void buildParametersWithCrunchyPrefix() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.CRUNCHY)
            .build();
    assertThat(parameters.getVariant()).isEqualTo(EcdsaParameters.Variant.CRUNCHY);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void buildParametersWithIeeeP1363Encoding() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters.getSignatureEncoding())
        .isEqualTo(EcdsaParameters.SignatureEncoding.IEEE_P1363);
  }

  @Test
  public void buildParametersWithDerEncoding() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters.getSignatureEncoding()).isEqualTo(EcdsaParameters.SignatureEncoding.DER);
  }

  @Test
  public void buildParametersWithP256AndSha256() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters.getCurveType()).isEqualTo(EcdsaParameters.CurveType.NIST_P256);
    assertThat(parameters.getHashType()).isEqualTo(EcdsaParameters.HashType.SHA256);
  }

  @Test
  public void buildParametersWithP384AndSha384() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P384)
            .setHashType(EcdsaParameters.HashType.SHA384)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters.getCurveType()).isEqualTo(EcdsaParameters.CurveType.NIST_P384);
    assertThat(parameters.getHashType()).isEqualTo(EcdsaParameters.HashType.SHA384);
  }

  @Test
  public void buildParametersWithP521AndSha512() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P521)
            .setHashType(EcdsaParameters.HashType.SHA512)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters.getCurveType()).isEqualTo(EcdsaParameters.CurveType.NIST_P521);
    assertThat(parameters.getHashType()).isEqualTo(EcdsaParameters.HashType.SHA512);
  }

  @Test
  public void buildWithoutSettingSignatureEncoding_fails() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> EcdsaParameters.builder()
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build());
  }

  @Test
  public void buildWithoutSettingCurveType_fails() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build());
  }

  @Test
  public void buildWithoutSettingHashType_fails() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build());
  }

  @Test
  public void buildWithVariantSetToNull_fails() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(null)
            .build());
  }

  @Test
  public void toParameterSpec_returnsSameSpecAsEllipticCurvesUtil() throws Exception {
    assertThat(
            EllipticCurvesUtil.isSameEcParameterSpec(
                EcdsaParameters.CurveType.NIST_P256.toParameterSpec(),
                EllipticCurvesUtil.NIST_P256_PARAMS))
        .isTrue();
    assertThat(
            EllipticCurvesUtil.isSameEcParameterSpec(
                EcdsaParameters.CurveType.NIST_P384.toParameterSpec(),
                EllipticCurvesUtil.NIST_P384_PARAMS))
        .isTrue();
    assertThat(
            EllipticCurvesUtil.isSameEcParameterSpec(
                EcdsaParameters.CurveType.NIST_P521.toParameterSpec(),
                EllipticCurvesUtil.NIST_P521_PARAMS))
        .isTrue();
  }

  @Test
  public void fromParameterSpec() throws Exception {
    assertThat(EcdsaParameters.CurveType.fromParameterSpec(EllipticCurvesUtil.NIST_P256_PARAMS))
        .isEqualTo(EcdsaParameters.CurveType.NIST_P256);
    assertThat(EcdsaParameters.CurveType.fromParameterSpec(EllipticCurvesUtil.NIST_P384_PARAMS))
        .isEqualTo(EcdsaParameters.CurveType.NIST_P384);
    assertThat(EcdsaParameters.CurveType.fromParameterSpec(EllipticCurvesUtil.NIST_P521_PARAMS))
        .isEqualTo(EcdsaParameters.CurveType.NIST_P521);
  }

  @Test
  public void testEqualsAndEqualHashCode() throws Exception {
    EcdsaParameters parameters1 =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    EcdsaParameters parameters2 =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();

    assertThat(parameters1).isEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isEqualTo(parameters2.hashCode());
  }

  @Test
  public void testNotEqual() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    assertThat(parameters)
        .isNotEqualTo(
            EcdsaParameters.builder()
                .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
                .setCurveType(EcdsaParameters.CurveType.NIST_P256)
                .setHashType(EcdsaParameters.HashType.SHA256)
                .setVariant(EcdsaParameters.Variant.NO_PREFIX)
                .build());
    assertThat(parameters)
        .isNotEqualTo(
            EcdsaParameters.builder()
                .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                .setCurveType(EcdsaParameters.CurveType.NIST_P384)
                .setHashType(EcdsaParameters.HashType.SHA384)
                .setVariant(EcdsaParameters.Variant.NO_PREFIX)
                .build());
    assertThat(parameters)
        .isNotEqualTo(
            EcdsaParameters.builder()
                .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                .setCurveType(EcdsaParameters.CurveType.NIST_P521)
                .setHashType(EcdsaParameters.HashType.SHA512)
                .setVariant(EcdsaParameters.Variant.NO_PREFIX)
                .build());
    assertThat(parameters)
        .isNotEqualTo(
            EcdsaParameters.builder()
                .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                .setCurveType(EcdsaParameters.CurveType.NIST_P256)
                .setHashType(EcdsaParameters.HashType.SHA256)
                .setVariant(EcdsaParameters.Variant.TINK)
                .build());
    Object hmacParameters =
        HmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(21)
            .setHashType(HmacParameters.HashType.SHA256)
            .build();
    assertThat(parameters.equals(hmacParameters)).isFalse();
  }
}
