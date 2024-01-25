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
import static com.google.crypto.tink.internal.testing.Asserts.assertEqualWhenValueParsed;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.proto.AesCmacKeyFormat;
import com.google.crypto.tink.proto.AesCmacParams;
import com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat;
import com.google.crypto.tink.proto.AesCtrKeyFormat;
import com.google.crypto.tink.proto.AesCtrParams;
import com.google.crypto.tink.proto.AesEaxKeyFormat;
import com.google.crypto.tink.proto.AesEaxParams;
import com.google.crypto.tink.proto.AesGcmKeyFormat;
import com.google.crypto.tink.proto.AesGcmSivKeyFormat;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKeyFormat;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.KmsEnvelopeAeadKey;
import com.google.crypto.tink.proto.KmsEnvelopeAeadKeyFormat;
import com.google.crypto.tink.proto.OutputPrefixType;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class LegacyKmsEnvelopeAeadProtoSerializationTest {
  private static final AeadParameters CHACHA20POLY1305_PARAMETERS =
      ChaCha20Poly1305Parameters.create(ChaCha20Poly1305Parameters.Variant.NO_PREFIX);

  private static final KeyTemplate CHACHA20POLY1305_RAW_TEMPLATE =
      KeyTemplate.newBuilder()
          .setTypeUrl("type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key")
          .setOutputPrefixType(OutputPrefixType.RAW)
          .build();

  private static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey";

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  @BeforeClass
  public static void setUp() throws Exception {
    MacConfig.register();
    AeadConfig.register();
    LegacyKmsEnvelopeAeadProtoSerialization.register(registry);
    // Also register the AesGcmSivProtoSerialization if we don't have conscrypt.
    // We anyhow only want to parse and serialize.
    AesGcmSivProtoSerialization.register();
  }

  @Test
  public void registerTwice() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    LegacyKmsAeadProtoSerialization.register(registry);
    LegacyKmsAeadProtoSerialization.register(registry);
  }

  @Test
  public void serializeParseParameters_aesGcm_works() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("someOtherKeyUri")
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

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            KmsEnvelopeAeadKeyFormat.newBuilder()
                .setKekUri("someOtherKeyUri")
                .setDekTemplate(
                    KeyTemplate.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.AesGcmKey")
                        .setValue(
                            AesGcmKeyFormat.newBuilder().setKeySize(16).build().toByteString())
                        .setOutputPrefixType(OutputPrefixType.RAW)
                        .build())
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(KmsEnvelopeAeadKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_xChaCha20Poly1305_works() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("someOtherKeyUriForAnXChaChaKey")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_XCHACHA20POLY1305)
            .setDekParametersForNewKeys(XChaCha20Poly1305Parameters.create())
            .build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            KmsEnvelopeAeadKeyFormat.newBuilder()
                .setKekUri("someOtherKeyUriForAnXChaChaKey")
                .setDekTemplate(
                    KeyTemplate.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key")
                        .setOutputPrefixType(OutputPrefixType.RAW)
                        .build())
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(KmsEnvelopeAeadKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_chaCha20Poly1305_works() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("someArbitrarykeyUri723")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_CHACHA20POLY1305)
            .setDekParametersForNewKeys(CHACHA20POLY1305_PARAMETERS)
            .build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            KmsEnvelopeAeadKeyFormat.newBuilder()
                .setKekUri("someArbitrarykeyUri723")
                .setDekTemplate(CHACHA20POLY1305_RAW_TEMPLATE)
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(KmsEnvelopeAeadKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_aesCtrHmac_works() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("someEaxOtherKeyUri")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_CTR_HMAC)
            .setDekParametersForNewKeys(
                AesCtrHmacAeadParameters.builder()
                    .setAesKeySizeBytes(16)
                    .setHmacKeySizeBytes(32)
                    .setTagSizeBytes(32)
                    .setIvSizeBytes(16)
                    .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                    .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                    .build())
            .build();

    AesCtrKeyFormat aesCtrKeyFormat =
        AesCtrKeyFormat.newBuilder()
            .setParams(AesCtrParams.newBuilder().setIvSize(16).build())
            .setKeySize(16)
            .build();
    HmacKeyFormat hmacKeyFormat =
        HmacKeyFormat.newBuilder()
            .setParams(HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(32).build())
            .setKeySize(32)
            .build();
    AesCtrHmacAeadKeyFormat format =
        AesCtrHmacAeadKeyFormat.newBuilder()
            .setAesCtrKeyFormat(aesCtrKeyFormat)
            .setHmacKeyFormat(hmacKeyFormat)
            .build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            KmsEnvelopeAeadKeyFormat.newBuilder()
                .setKekUri("someEaxOtherKeyUri")
                .setDekTemplate(
                    KeyTemplate.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey")
                        .setOutputPrefixType(OutputPrefixType.RAW)
                        .setValue(format.toByteString())
                        .build())
                .build());
    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(KmsEnvelopeAeadKeyFormat.parser(), serialized, serialization);
  }

  @Test
  public void serializeParseParameters_aesEax_works() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("someEaxOtherKeyUri")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_EAX)
            .setDekParametersForNewKeys(
                AesEaxParameters.builder()
                    .setIvSizeBytes(12)
                    .setKeySizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesEaxParameters.Variant.NO_PREFIX)
                    .build())
            .build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            KmsEnvelopeAeadKeyFormat.newBuilder()
                .setKekUri("someEaxOtherKeyUri")
                .setDekTemplate(
                    KeyTemplate.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.AesEaxKey")
                        .setValue(
                            AesEaxKeyFormat.newBuilder()
                                .setKeySize(16)
                                .setParams(AesEaxParams.newBuilder().setIvSize(12))
                                .build()
                                .toByteString())
                        .setOutputPrefixType(OutputPrefixType.RAW)
                        .build())
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(KmsEnvelopeAeadKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_aesGcmSiv_works() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("someEaxOtherKeyUri")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_GCM_SIV)
            .setDekParametersForNewKeys(
                AesGcmSivParameters.builder()
                    .setKeySizeBytes(16)
                    .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
                    .build())
            .build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            KmsEnvelopeAeadKeyFormat.newBuilder()
                .setKekUri("someEaxOtherKeyUri")
                .setDekTemplate(
                    KeyTemplate.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.AesGcmSivKey")
                        .setValue(
                            AesGcmSivKeyFormat.newBuilder().setKeySize(16).build().toByteString())
                        .setOutputPrefixType(OutputPrefixType.RAW)
                        .build())
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(KmsEnvelopeAeadKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void parseParameters_macTypeUrl_throws() throws Exception {
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            KmsEnvelopeAeadKeyFormat.newBuilder()
                .setKekUri("someEaxOtherKeyUri")
                .setDekTemplate(
                    KeyTemplate.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.AesCmacParams")
                        .setValue(
                            AesCmacKeyFormat.newBuilder()
                                .setKeySize(32)
                                .setParams(AesCmacParams.newBuilder().setTagSize(16).build())
                                .build()
                                .toByteString())
                        .setOutputPrefixType(OutputPrefixType.RAW)
                        .build())
                .build());

    GeneralSecurityException thrown =
        assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
    // Check the message to ensure that the exception is not thrown when parsing the key template
    // but instead when computing the DekParsingStrategy from the class.
    assertThat(thrown).hasMessageThat().contains("Unsupported DEK parameters when");
  }

  /**
   * Tests that when parsing, the OutputPrefixType of the template in DekKeyTemplate is ignored and
   * RAW is used instead.
   */
  @Test
  public void parseParameters_outputPrefixUnknown_isIgnored() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("someEaxOtherKeyUri")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_XCHACHA20POLY1305)
            .setDekParametersForNewKeys(XChaCha20Poly1305Parameters.create())
            .build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            KmsEnvelopeAeadKeyFormat.newBuilder()
                .setKekUri("someEaxOtherKeyUri")
                .setDekTemplate(
                    KeyTemplate.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key")
                        .setOutputPrefixType(OutputPrefixType.UNKNOWN_PREFIX)
                        .build())
                .build());

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  /**
   * Tests that when parsing, the OutputPrefixType of the template in DekKeyTemplate is ignored and
   * RAW is used instead.
   */
  @Test
  public void parseParameters_outputPrefixTink_isIgnored() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("someEaxOtherKeyUri")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_XCHACHA20POLY1305)
            .setDekParametersForNewKeys(XChaCha20Poly1305Parameters.create())
            .build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            KmsEnvelopeAeadKeyFormat.newBuilder()
                .setKekUri("someEaxOtherKeyUri")
                .setDekTemplate(
                    KeyTemplate.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key")
                        .setOutputPrefixType(OutputPrefixType.TINK)
                        .build())
                .build());

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseKey_aesGcm_works() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("someKeyUriForKeyTests")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_XCHACHA20POLY1305)
            .setDekParametersForNewKeys(XChaCha20Poly1305Parameters.create())
            .build();
    LegacyKmsEnvelopeAeadKey key = LegacyKmsEnvelopeAeadKey.create(parameters);

    KmsEnvelopeAeadKeyFormat format =
        KmsEnvelopeAeadKeyFormat.newBuilder()
            .setKekUri("someKeyUriForKeyTests")
            .setDekTemplate(
                KeyTemplate.newBuilder()
                    .setTypeUrl("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key")
                    .setOutputPrefixType(OutputPrefixType.RAW))
            .build();

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            TYPE_URL,
            KmsEnvelopeAeadKey.newBuilder().setParams(format).build().toByteString(),
            KeyMaterialType.REMOTE,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, /* access= */ null);
    assertEqualWhenValueParsed(KmsEnvelopeAeadKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void parseKey_wrongVersion_throws() throws Exception {
    KmsEnvelopeAeadKeyFormat format =
        KmsEnvelopeAeadKeyFormat.newBuilder()
            .setKekUri("someKeyUriForKeyTests")
            .setDekTemplate(
                KeyTemplate.newBuilder()
                    .setTypeUrl("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key")
                    .setOutputPrefixType(OutputPrefixType.RAW))
            .build();

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            TYPE_URL,
            KmsEnvelopeAeadKey.newBuilder().setVersion(1).setParams(format).build().toByteString(),
            KeyMaterialType.REMOTE,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
  }

  @Test
  public void parseKey_notRaw_throws() throws Exception {
    KmsEnvelopeAeadKeyFormat format =
        KmsEnvelopeAeadKeyFormat.newBuilder()
            .setKekUri("someKeyUriForKeyTests")
            .setDekTemplate(
                KeyTemplate.newBuilder()
                    .setTypeUrl("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key")
                    .setOutputPrefixType(OutputPrefixType.RAW))
            .build();

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            TYPE_URL,
            KmsEnvelopeAeadKey.newBuilder().setParams(format).build().toByteString(),
            KeyMaterialType.REMOTE,
            OutputPrefixType.TINK,
            /* idRequirement= */ 123);

    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
  }
}
