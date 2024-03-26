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

package com.google.crypto.tink.aead;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;
import static org.junit.Assert.assertThrows;

import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class LegacyKmsEnvelopeAeadParametersTest {
  @BeforeClass
  public static void registerAead() throws Exception {
    AeadConfig.register();
  }

  private static final AeadParameters AES_GCM_PARAMETERS =
      exceptionIsBug(
          () ->
              AesGcmParameters.builder()
                  .setIvSizeBytes(12)
                  .setKeySizeBytes(16)
                  .setTagSizeBytes(16)
                  .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                  .build());
  private static final AeadParameters CHACHA20POLY1305_PARAMETERS =
      ChaCha20Poly1305Parameters.create(ChaCha20Poly1305Parameters.Variant.NO_PREFIX);
  private static final AeadParameters XCHACHA20POLY1305_PARAMETERS =
      XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.NO_PREFIX);
  private static final AeadParameters AES_EAX_PARAMETERS =
      exceptionIsBug(
          () ->
              AesEaxParameters.builder()
                  .setIvSizeBytes(16)
                  .setKeySizeBytes(16)
                  .setTagSizeBytes(16)
                  .setVariant(AesEaxParameters.Variant.NO_PREFIX)
                  .build());
  public static final AesCtrHmacAeadParameters AES_CTR_HMAC_PARAMETERS =
      exceptionIsBug(
          () ->
              AesCtrHmacAeadParameters.builder()
                  .setAesKeySizeBytes(16)
                  .setHmacKeySizeBytes(32)
                  .setTagSizeBytes(16)
                  .setIvSizeBytes(16)
                  .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                  .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                  .build());
  public static final AesGcmSivParameters AES_GCM_SIV_PARAMETERS =
      exceptionIsBug(
          () ->
              AesGcmSivParameters.builder()
                  .setKeySizeBytes(16)
                  .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
                  .build());

  @Test
  public void createBasic_checkValues_works() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("SomeKekUri")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_GCM)
            .setDekParametersForNewKeys(AES_GCM_PARAMETERS)
            .build();
    assertThat(parameters.getVariant())
        .isEqualTo(LegacyKmsEnvelopeAeadParameters.Variant.NO_PREFIX);
    assertThat(parameters.getKekUri()).isEqualTo("SomeKekUri");
    assertThat(parameters.getDekParsingStrategy())
        .isEqualTo(LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_GCM);
    assertThat(parameters.getDekParametersForNewKeys()).isEqualTo(AES_GCM_PARAMETERS);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void createWithTinkPrefix_checkValues_works() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setVariant(LegacyKmsEnvelopeAeadParameters.Variant.TINK)
            .setKekUri("SomeKekUri")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_GCM)
            .setDekParametersForNewKeys(AES_GCM_PARAMETERS)
            .build();
    assertThat(parameters.getVariant()).isEqualTo(LegacyKmsEnvelopeAeadParameters.Variant.TINK);
    assertThat(parameters.getKekUri()).isEqualTo("SomeKekUri");
    assertThat(parameters.getDekParsingStrategy())
        .isEqualTo(LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_GCM);
    assertThat(parameters.getDekParametersForNewKeys()).isEqualTo(AES_GCM_PARAMETERS);
    assertThat(parameters.hasIdRequirement()).isTrue();
  }

  @Test
  public void createWithChaChaParameters_works() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("SomeOtherKekUri")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_CHACHA20POLY1305)
            .setDekParametersForNewKeys(CHACHA20POLY1305_PARAMETERS)
            .build();
    assertThat(parameters.getVariant())
        .isEqualTo(LegacyKmsEnvelopeAeadParameters.Variant.NO_PREFIX);
    assertThat(parameters.getKekUri()).isEqualTo("SomeOtherKekUri");
    assertThat(parameters.getDekParsingStrategy())
        .isEqualTo(LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_CHACHA20POLY1305);
    assertThat(parameters.getDekParametersForNewKeys()).isEqualTo(CHACHA20POLY1305_PARAMETERS);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void createWithXChaChaParameters_works() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("SomeOtherKekUri")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_XCHACHA20POLY1305)
            .setDekParametersForNewKeys(XCHACHA20POLY1305_PARAMETERS)
            .build();
    assertThat(parameters.getVariant())
        .isEqualTo(LegacyKmsEnvelopeAeadParameters.Variant.NO_PREFIX);
    assertThat(parameters.getKekUri()).isEqualTo("SomeOtherKekUri");
    assertThat(parameters.getDekParsingStrategy())
        .isEqualTo(LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_XCHACHA20POLY1305);
    assertThat(parameters.getDekParametersForNewKeys()).isEqualTo(XCHACHA20POLY1305_PARAMETERS);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void createWithEaxParameters_works() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("SomeOtherKekUri")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_EAX)
            .setDekParametersForNewKeys(AES_EAX_PARAMETERS)
            .build();
    assertThat(parameters.getVariant())
        .isEqualTo(LegacyKmsEnvelopeAeadParameters.Variant.NO_PREFIX);
    assertThat(parameters.getKekUri()).isEqualTo("SomeOtherKekUri");
    assertThat(parameters.getDekParsingStrategy())
        .isEqualTo(LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_EAX);
    assertThat(parameters.getDekParametersForNewKeys()).isEqualTo(AES_EAX_PARAMETERS);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void createAesCtrHmacParameters_works() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("SomeOtherKekUri")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_EAX)
            .setDekParametersForNewKeys(AES_EAX_PARAMETERS)
            .build();
    assertThat(parameters.getVariant())
        .isEqualTo(LegacyKmsEnvelopeAeadParameters.Variant.NO_PREFIX);
    assertThat(parameters.getKekUri()).isEqualTo("SomeOtherKekUri");
    assertThat(parameters.getDekParsingStrategy())
        .isEqualTo(LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_EAX);
    assertThat(parameters.getDekParametersForNewKeys()).isEqualTo(AES_EAX_PARAMETERS);
    assertThat(parameters.hasIdRequirement()).isFalse();
  }

  @Test
  public void createWithDekParametersMismatch_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            LegacyKmsEnvelopeAeadParameters.builder()
                .setKekUri("SomeKekUri")
                .setDekParsingStrategy(
                    LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_EAX)
                .setDekParametersForNewKeys(AES_GCM_PARAMETERS)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            LegacyKmsEnvelopeAeadParameters.builder()
                .setKekUri("SomeKekUri")
                .setDekParsingStrategy(
                    LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_XCHACHA20POLY1305)
                .setDekParametersForNewKeys(CHACHA20POLY1305_PARAMETERS)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            LegacyKmsEnvelopeAeadParameters.builder()
                .setKekUri("SomeKekUri")
                .setDekParsingStrategy(
                    LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_CHACHA20POLY1305)
                .setDekParametersForNewKeys(XCHACHA20POLY1305_PARAMETERS)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            LegacyKmsEnvelopeAeadParameters.builder()
                .setKekUri("SomeKekUri")
                .setDekParsingStrategy(
                    LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_CTR_HMAC)
                .setDekParametersForNewKeys(AES_GCM_SIV_PARAMETERS)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            LegacyKmsEnvelopeAeadParameters.builder()
                .setKekUri("SomeKekUri")
                .setDekParsingStrategy(
                    LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_GCM_SIV)
                .setDekParametersForNewKeys(AES_GCM_PARAMETERS)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            LegacyKmsEnvelopeAeadParameters.builder()
                .setKekUri("SomeKekUri")
                .setDekParsingStrategy(
                    LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_GCM)
                .setDekParametersForNewKeys(AES_EAX_PARAMETERS)
                .build());
  }

  @Test
  public void build_setDekParametersForNewKeysWithIdRequirement_throws() throws Exception {
    AeadParameters aesGcm128Tink =
        AesGcmParameters.builder()
            .setIvSizeBytes(12)
            .setKeySizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.TINK)
            .build();
    LegacyKmsEnvelopeAeadParameters.Builder parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("SomeKekUri")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_GCM)
            .setDekParametersForNewKeys(aesGcm128Tink);
    assertThrows(GeneralSecurityException.class, parameters::build);
  }

  @Test
  public void build_doNotSetKekUri_throws() throws Exception {
    AeadParameters aesGcm128Raw =
        AesGcmParameters.builder()
            .setIvSizeBytes(12)
            .setKeySizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build();
    LegacyKmsEnvelopeAeadParameters.Builder parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_GCM)
            .setDekParametersForNewKeys(aesGcm128Raw);
    assertThrows(GeneralSecurityException.class, parameters::build);
  }

  @Test
  public void build_doNotSetDekTypeUrlForParsing_throws() throws Exception {
    AeadParameters aesGcm128Raw =
        AesGcmParameters.builder()
            .setIvSizeBytes(12)
            .setKeySizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build();
    LegacyKmsEnvelopeAeadParameters.Builder parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("SomeKekUri")
            .setDekParametersForNewKeys(aesGcm128Raw);
    assertThrows(GeneralSecurityException.class, parameters::build);
  }

  @Test
  public void createBasic_doNotSetParameters_throws() throws Exception {
    LegacyKmsEnvelopeAeadParameters.Builder parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("SomeKekUri")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_GCM);
    assertThrows(GeneralSecurityException.class, parameters::build);
  }

  @Test
  public void testEqualityAndHash() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters1 =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("SomeKekUri")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_GCM)
            .setDekParametersForNewKeys(AES_GCM_PARAMETERS)
            .build();
    LegacyKmsEnvelopeAeadParameters parameters1Copy =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("SomeKekUri")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_GCM)
            .setDekParametersForNewKeys(
                AesGcmParameters.builder()
                    .setIvSizeBytes(12)
                    .setKeySizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                    .build())
            .build();
    LegacyKmsEnvelopeAeadParameters parametersWithDifferentKekUri =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("DifferentSomeKekUri")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_GCM)
            .setDekParametersForNewKeys(AES_GCM_PARAMETERS)
            .build();
    LegacyKmsEnvelopeAeadParameters parametersWithDifferentDekKeySize =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("DifferentSomeKekUri")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_GCM)
            .setDekParametersForNewKeys(
                AesGcmParameters.builder()
                    .setIvSizeBytes(12)
                    // 32 Byte Keys
                    .setKeySizeBytes(32)
                    .setTagSizeBytes(16)
                    .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                    .build())
            .build();

    assertThat(parameters1).isEqualTo(parameters1Copy);
    assertThat(parameters1).isNotEqualTo(parametersWithDifferentKekUri);
    assertThat(parameters1).isNotEqualTo(parametersWithDifferentDekKeySize);

    assertThat(parameters1.hashCode()).isEqualTo(parameters1Copy.hashCode());
    assertThat(parameters1.hashCode()).isNotEqualTo(parametersWithDifferentKekUri.hashCode());
    assertThat(parameters1.hashCode()).isNotEqualTo(parametersWithDifferentDekKeySize.hashCode());
  }
}
