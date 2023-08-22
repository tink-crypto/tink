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

package com.google.crypto.tink.hybrid;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.aead.AesCtrHmacAeadParameters;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.aead.ChaCha20Poly1305Parameters;
import com.google.crypto.tink.aead.XChaCha20Poly1305Parameters;
import com.google.crypto.tink.daead.AesSivParameters;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public final class EciesParametersTest {

  private static final Bytes SALT = Bytes.copyFrom(Hex.decode("2023af"));

  @DataPoints("curveTypes")
  public static final EciesParameters.CurveType[] NIST_CURVE_TYPES =
      new EciesParameters.CurveType[] {
        EciesParameters.CurveType.NIST_P256,
        EciesParameters.CurveType.NIST_P384,
        EciesParameters.CurveType.NIST_P521,
      };

  @DataPoints("hashTypes")
  public static final EciesParameters.HashType[] HASH_TYPES =
      new EciesParameters.HashType[] {
        EciesParameters.HashType.SHA1,
        EciesParameters.HashType.SHA224,
        EciesParameters.HashType.SHA256,
        EciesParameters.HashType.SHA384,
        EciesParameters.HashType.SHA512,
      };

  @DataPoints("pointFormats")
  public static final EciesParameters.PointFormat[] POINT_FORMATS =
      new EciesParameters.PointFormat[] {
        EciesParameters.PointFormat.COMPRESSED,
        EciesParameters.PointFormat.UNCOMPRESSED,
        EciesParameters.PointFormat.LEGACY_UNCOMPRESSED,
      };

  @DataPoints("variants")
  public static final EciesParameters.Variant[] VARIANTS =
      new EciesParameters.Variant[] {
        EciesParameters.Variant.TINK,
        EciesParameters.Variant.CRUNCHY,
        EciesParameters.Variant.NO_PREFIX,
      };

  @Theory
  public void buildWithNistCurvesAndAesGcmDem_hasExpectedValues(
      @FromDataPoints("variants") EciesParameters.Variant variant,
      @FromDataPoints("hashTypes") EciesParameters.HashType hashType,
      @FromDataPoints("curveTypes") EciesParameters.CurveType curveType,
      @FromDataPoints("pointFormats") EciesParameters.PointFormat pointFormat)
      throws Exception {
    Parameters aesGcmParameters =
        AesGcmParameters.builder()
            .setIvSizeBytes(12)
            .setKeySizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build();

    EciesParameters params =
        EciesParameters.builder()
            .setCurveType(curveType)
            .setHashType(hashType)
            .setNistCurvePointFormat(pointFormat)
            .setVariant(variant)
            .setDemParameters(aesGcmParameters)
            .setSalt(SALT)
            .build();

    assertThat(params.getVariant()).isEqualTo(variant);
    assertThat(params.getCurveType()).isEqualTo(curveType);
    assertThat(params.getHashType()).isEqualTo(hashType);
    assertThat(params.getNistCurvePointFormat()).isEqualTo(pointFormat);
    assertThat(params.getDemParameters()).isEqualTo(aesGcmParameters);
    assertThat(params.getSalt()).isEqualTo(SALT);
  }

  @Test
  public void buildWithAesCtrHmacAeadDem_succeeds() throws Exception {
    Parameters aesCtrHmacAeadParameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(32)
            .setTagSizeBytes(16)
            .setIvSizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();

    EciesParameters params =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P521)
            .setHashType(EciesParameters.HashType.SHA512)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setVariant(EciesParameters.Variant.TINK)
            .setDemParameters(aesCtrHmacAeadParameters)
            .setSalt(SALT)
            .build();

    assertThat(params.getDemParameters()).isEqualTo(aesCtrHmacAeadParameters);
  }

  @Theory
  public void buildWithXChaCha20Poly1305Dem_succeeds() throws Exception {
    Parameters xChaCha20Poly1305Parameters = XChaCha20Poly1305Parameters.create();

    EciesParameters params =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
            .setVariant(EciesParameters.Variant.CRUNCHY)
            .setDemParameters(xChaCha20Poly1305Parameters)
            .setSalt(SALT)
            .build();

    assertThat(params.getDemParameters()).isEqualTo(xChaCha20Poly1305Parameters);
  }

  @Theory
  public void buildWithAesSivDem_succeeds() throws Exception {
    Parameters aesSivParameters =
        AesSivParameters.builder()
            .setKeySizeBytes(64)
            .setVariant(AesSivParameters.Variant.NO_PREFIX)
            .build();

    EciesParameters params =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(aesSivParameters)
            .setSalt(SALT)
            .build();

    assertThat(params.getDemParameters()).isEqualTo(aesSivParameters);
  }

  @Theory
  public void buildWithX25519_succeeds(
      @FromDataPoints("variants") EciesParameters.Variant variant,
      @FromDataPoints("hashTypes") EciesParameters.HashType hashType)
      throws Exception {
    Parameters xChaCha20Poly1305Parameters = XChaCha20Poly1305Parameters.create();

    EciesParameters params =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.X25519)
            .setHashType(hashType)
            .setVariant(variant)
            .setDemParameters(xChaCha20Poly1305Parameters)
            .setSalt(SALT)
            .build();

    assertThat(params.getCurveType()).isEqualTo(EciesParameters.CurveType.X25519);
    assertThat(params.getNistCurvePointFormat()).isEqualTo(null);
    assertThat(params.getHashType()).isEqualTo(hashType);
    assertThat(params.getVariant()).isEqualTo(variant);
  }

  @Test
  public void buildWithX25519NistCurveSet_fails() throws Exception {
    Parameters xChaCha20Poly1305Parameters = XChaCha20Poly1305Parameters.create();

    EciesParameters.Builder builder =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.X25519)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(xChaCha20Poly1305Parameters)
            .setSalt(SALT);

    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void buildWithoutSettingSalt_succeeds() throws Exception {
    EciesParameters parameters =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();

    assertThat(parameters.getSalt()).isNull();
  }

  @Test
  public void buildWithEmptySalt_succeeds() throws Exception {
    EciesParameters parameters =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .setSalt(Bytes.copyFrom("".getBytes(UTF_8)))
            .build();

    assertThat(parameters.getSalt()).isNull();
  }

  @Test
  public void clearSaltWithEmptyString_succeeds() throws Exception {
    EciesParameters parameters =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .setSalt(Bytes.copyFrom("Some Salt".getBytes(UTF_8)))
            .setSalt(Bytes.copyFrom("".getBytes(UTF_8)))
            .build();

    assertThat(parameters.getSalt()).isNull();
  }

  @Theory
  public void buildWithDefaultVariant_hasNoPrefix() throws Exception {
    Parameters demParameters = XChaCha20Poly1305Parameters.create();
    EciesParameters params =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(demParameters)
            .setSalt(SALT)
            .build();

    assertThat(params.getVariant()).isEqualTo(EciesParameters.Variant.NO_PREFIX);
  }

  @Test
  public void buildWithoutCurveType_fails() throws Exception {
    EciesParameters.Builder builder =
        EciesParameters.builder()
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(XChaCha20Poly1305Parameters.create());

    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void buildWithoutHashType_fails() throws Exception {
    EciesParameters.Builder builder =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(XChaCha20Poly1305Parameters.create());

    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void buildWithoutPointFormat_fails() throws Exception {
    EciesParameters.Builder builder =
        EciesParameters.builder()
            .setHashType(EciesParameters.HashType.SHA256)
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(XChaCha20Poly1305Parameters.create());

    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void buildWithoutDemParameters_fails() throws Exception {
    EciesParameters.Builder builder =
        EciesParameters.builder()
            .setHashType(EciesParameters.HashType.SHA256)
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
            .setVariant(EciesParameters.Variant.NO_PREFIX);

    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void setUnsupportedDemParameters_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            EciesParameters.builder()
                .setHashType(EciesParameters.HashType.SHA256)
                .setCurveType(EciesParameters.CurveType.NIST_P256)
                .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
                .setVariant(EciesParameters.Variant.NO_PREFIX)
                .setDemParameters(ChaCha20Poly1305Parameters.create())
                .build());
  }

  @Test
  public void setDemParametersWithIdRequirement_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            EciesParameters.builder()
                .setHashType(EciesParameters.HashType.SHA256)
                .setCurveType(EciesParameters.CurveType.NIST_P256)
                .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
                .setVariant(EciesParameters.Variant.NO_PREFIX)
                .setDemParameters(
                    XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK))
                .build());
  }

  @Test
  public void buildWithVariantSetToNull_fails() throws Exception {
    EciesParameters.Builder builder =
        EciesParameters.builder()
            .setHashType(EciesParameters.HashType.SHA256)
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .setVariant(null);

    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void buildWithNoPrefix_doesNotHaveIdRequirement() throws Exception {
    EciesParameters noPrefixParams =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();

    assertThat(noPrefixParams.hasIdRequirement()).isFalse();
  }

  @Test
  public void buildWithTink_hasIdRequirement() throws Exception {
    EciesParameters tinkParams =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setVariant(EciesParameters.Variant.TINK)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();

    assertThat(tinkParams.hasIdRequirement()).isTrue();
  }

  @Test
  public void buildWithCrunchy_hasIdRequirement() throws Exception {

    EciesParameters crunchyParams =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setVariant(EciesParameters.Variant.CRUNCHY)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();

    assertThat(crunchyParams.hasIdRequirement()).isTrue();
  }

  @Test
  public void testEqualsAndEqualHashCode() throws Exception {
    EciesParameters params =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .setSalt(SALT)
            .build();
    EciesParameters duplicateParams =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .setSalt(SALT)
            .build();

    assertThat(params).isEqualTo(duplicateParams);
    assertThat(params.hashCode()).isEqualTo(duplicateParams.hashCode());
  }

  @Test
  public void parametersWithDifferentVariants_areNotEqual() throws Exception {
    EciesParameters crunchyParams =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setVariant(EciesParameters.Variant.CRUNCHY)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();

    EciesParameters tinkParams =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setVariant(EciesParameters.Variant.TINK)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();

    assertThat(crunchyParams).isNotEqualTo(tinkParams);
    assertThat(crunchyParams.hashCode()).isNotEqualTo(tinkParams.hashCode());
  }

  @Test
  public void parametersWithDifferentCurveTypes_areNotEqual() throws Exception {
    EciesParameters p256Params =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();

    EciesParameters p521Params =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P521)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();

    assertThat(p256Params).isNotEqualTo(p521Params);
    assertThat(p256Params.hashCode()).isNotEqualTo(p521Params.hashCode());
  }

  @Test
  public void parametersWithDifferentHashTypes_areNotEqual() throws Exception {
    EciesParameters sha256Params =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();

    EciesParameters sha512Params =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA512)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();

    assertThat(sha256Params).isNotEqualTo(sha512Params);
    assertThat(sha256Params.hashCode()).isNotEqualTo(sha512Params.hashCode());
  }

  @Test
  public void parametersWithDifferenPointFormats_areNotEqual() throws Exception {
    EciesParameters compressedParams =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();

    EciesParameters uncompressedParams =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();

    assertThat(compressedParams).isNotEqualTo(uncompressedParams);
    assertThat(compressedParams.hashCode()).isNotEqualTo(uncompressedParams.hashCode());
  }

  @Test
  public void parametersWithDifferentDemParameters_areNotEqual() throws Exception {
    EciesParameters aesSivParams =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setDemParameters(
                AesSivParameters.builder()
                    .setKeySizeBytes(64)
                    .setVariant(AesSivParameters.Variant.NO_PREFIX)
                    .build())
            .build();

    EciesParameters xChaCha20Poly1305Params =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();

    assertThat(aesSivParams).isNotEqualTo(xChaCha20Poly1305Params);
    assertThat(aesSivParams.hashCode()).isNotEqualTo(xChaCha20Poly1305Params.hashCode());
  }

  @Test
  public void parametersWithDifferentSalts_areNotEqual() throws Exception {
    EciesParameters nonEmptySaltParams =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .setSalt(SALT)
            .build();

    EciesParameters emptySaltParams =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .setSalt(Bytes.copyFrom("".getBytes(UTF_8)))
            .build();

    assertThat(emptySaltParams).isNotEqualTo(nonEmptySaltParams);
    assertThat(emptySaltParams.hashCode()).isNotEqualTo(nonEmptySaltParams.hashCode());
  }
}
