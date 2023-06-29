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

package com.google.crypto.tink.keyderivation;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;
import static com.google.crypto.tink.internal.testing.Asserts.assertEqualWhenValueParsed;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.XChaCha20Poly1305Parameters;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.prf.AesCmacPrfParameters;
import com.google.crypto.tink.prf.PrfConfig;
import com.google.crypto.tink.prf.PrfParameters;
import com.google.crypto.tink.proto.AesCmacPrfKeyFormat;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.proto.PrfBasedDeriverKeyFormat;
import com.google.crypto.tink.proto.PrfBasedDeriverParams;
import com.google.crypto.tink.proto.XChaCha20Poly1305KeyFormat;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class PrfBasedKeyDerivationKeyProtoSerializationTest {
  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  private static final PrfParameters PRF_PARAMETERS =
      exceptionIsBug(() -> AesCmacPrfParameters.create(16));
  private static final AesCmacPrfKeyFormat PRF_KEY_FORMAT_PROTO =
      AesCmacPrfKeyFormat.newBuilder().setVersion(0).setKeySize(16).build();

  private static final Parameters DERIVED_PARAMETERS_RAW =
      exceptionIsBug(() -> XChaCha20Poly1305Parameters.create());

  private static final Parameters DERIVED_PARAMETERS =
      exceptionIsBug(
          () -> XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK));
  private static final XChaCha20Poly1305KeyFormat DERIVED_KEY_FORMAT_PROTO =
      XChaCha20Poly1305KeyFormat.newBuilder().setVersion(0).build();

  @BeforeClass
  public static void register() throws Exception {
    AeadConfig.register();
    PrfConfig.register();

    PrfBasedKeyDerivationKeyProtoSerialization.register(registry);
  }

  @Test
  public void serializeParseParameters_raw() throws Exception {
    PrfBasedKeyDerivationParameters parameters =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(PRF_PARAMETERS)
            .setDerivedKeyParameters(DERIVED_PARAMETERS_RAW)
            .build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
            OutputPrefixType.RAW,
            PrfBasedDeriverKeyFormat.newBuilder()
                .setPrfKeyTemplate(
                    KeyTemplate.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.AesCmacPrfKey")
                        .setValue(PRF_KEY_FORMAT_PROTO.toByteString())
                        .setOutputPrefixType(OutputPrefixType.RAW))
                .setParams(
                    PrfBasedDeriverParams.newBuilder()
                        .setDerivedKeyTemplate(
                            KeyTemplate.newBuilder()
                                .setTypeUrl(
                                    "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key")
                                .setValue(DERIVED_KEY_FORMAT_PROTO.toByteString())
                                .setOutputPrefixType(OutputPrefixType.RAW)))
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(PrfBasedDeriverKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_tink_variant() throws Exception {
    PrfBasedKeyDerivationParameters parameters =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(PRF_PARAMETERS)
            .setDerivedKeyParameters(DERIVED_PARAMETERS)
            .build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
            OutputPrefixType.TINK,
            PrfBasedDeriverKeyFormat.newBuilder()
                .setPrfKeyTemplate(
                    KeyTemplate.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.AesCmacPrfKey")
                        .setValue(PRF_KEY_FORMAT_PROTO.toByteString())
                        .setOutputPrefixType(OutputPrefixType.RAW))
                .setParams(
                    PrfBasedDeriverParams.newBuilder()
                        .setDerivedKeyTemplate(
                            KeyTemplate.newBuilder()
                                .setTypeUrl(
                                    "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key")
                                .setValue(DERIVED_KEY_FORMAT_PROTO.toByteString())
                                .setOutputPrefixType(OutputPrefixType.TINK)))
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(PrfBasedDeriverKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParameters_unknownPrfParameters_throws() throws Exception {
    PrfBasedKeyDerivationParameters parameters =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(PRF_PARAMETERS)
            .setDerivedKeyParameters(
                new Parameters() {
                  @Override
                  public boolean hasIdRequirement() {
                    return false;
                  }
                })
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.serializeParameters(parameters, ProtoParametersSerialization.class));
  }

  @Test
  public void serializeParameters_unknownDerivedKeyParameters_throws() throws Exception {
    PrfBasedKeyDerivationParameters parameters =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(
                new PrfParameters() {
                  @Override
                  public boolean hasIdRequirement() {
                    return false;
                  }
                })
            .setDerivedKeyParameters(DERIVED_PARAMETERS)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.serializeParameters(parameters, ProtoParametersSerialization.class));
  }

  @Test
  public void parseParameters_outputPrefixMismatch_throws() throws Exception {
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
            OutputPrefixType.RAW, // Mismatch: RAW here
            PrfBasedDeriverKeyFormat.newBuilder()
                .setPrfKeyTemplate(
                    KeyTemplate.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.AesCmacPrfKey")
                        .setValue(PRF_KEY_FORMAT_PROTO.toByteString())
                        .setOutputPrefixType(OutputPrefixType.RAW))
                .setParams(
                    PrfBasedDeriverParams.newBuilder()
                        .setDerivedKeyTemplate(
                            KeyTemplate.newBuilder()
                                .setTypeUrl(
                                    "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key")
                                .setValue(DERIVED_KEY_FORMAT_PROTO.toByteString())
                                .setOutputPrefixType(OutputPrefixType.TINK))) // Mismatch: TINK here
                .build());
    assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
  }

  @Test
  public void parseParameters_invalidSerializations_badTypeUrl1_throws() throws Exception {
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
            OutputPrefixType.RAW,
            PrfBasedDeriverKeyFormat.newBuilder()
                .setPrfKeyTemplate(
                    KeyTemplate.newBuilder()
                        .setTypeUrl("Non Existent Type Url")
                        .setValue(PRF_KEY_FORMAT_PROTO.toByteString())
                        .setOutputPrefixType(OutputPrefixType.RAW))
                .setParams(
                    PrfBasedDeriverParams.newBuilder()
                        .setDerivedKeyTemplate(
                            KeyTemplate.newBuilder()
                                .setTypeUrl(
                                    "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key")
                                .setValue(DERIVED_KEY_FORMAT_PROTO.toByteString())
                                .setOutputPrefixType(OutputPrefixType.RAW)))
                .build());
    assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
  }

  @Test
  public void parseParameters_invalidSerializations_badTypeUrl2_throws() throws Exception {
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
            OutputPrefixType.RAW,
            PrfBasedDeriverKeyFormat.newBuilder()
                .setPrfKeyTemplate(
                    KeyTemplate.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.AesCmacPrfKey")
                        .setValue(PRF_KEY_FORMAT_PROTO.toByteString())
                        .setOutputPrefixType(OutputPrefixType.RAW))
                .setParams(
                    PrfBasedDeriverParams.newBuilder()
                        .setDerivedKeyTemplate(
                            KeyTemplate.newBuilder()
                                .setTypeUrl("Non Existent Type Url")
                                .setValue(DERIVED_KEY_FORMAT_PROTO.toByteString())
                                .setOutputPrefixType(OutputPrefixType.RAW)))
                .build());
    assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
  }

  @Test
  public void parseParameters_invalidSerializations_badValue1_throws() throws Exception {
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
            OutputPrefixType.RAW,
            PrfBasedDeriverKeyFormat.newBuilder()
                .setPrfKeyTemplate(
                    KeyTemplate.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.AesCmacPrfKey")
                        .setValue(ByteString.copyFrom(new byte[] {(byte) 0x80}))
                        .setOutputPrefixType(OutputPrefixType.RAW))
                .setParams(
                    PrfBasedDeriverParams.newBuilder()
                        .setDerivedKeyTemplate(
                            KeyTemplate.newBuilder()
                                .setTypeUrl(
                                    "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key")
                                .setValue(DERIVED_KEY_FORMAT_PROTO.toByteString())
                                .setOutputPrefixType(OutputPrefixType.RAW)))
                .build());
    assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
  }

  @Test
  public void parseParameters_invalidSerializations_badValue2_throws() throws Exception {
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
            OutputPrefixType.RAW,
            PrfBasedDeriverKeyFormat.newBuilder()
                .setPrfKeyTemplate(
                    KeyTemplate.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.AesCmacPrfKey")
                        .setValue(PRF_KEY_FORMAT_PROTO.toByteString())
                        .setOutputPrefixType(OutputPrefixType.RAW))
                .setParams(
                    PrfBasedDeriverParams.newBuilder()
                        .setDerivedKeyTemplate(
                            KeyTemplate.newBuilder()
                                .setTypeUrl(
                                    "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key")
                                .setValue(ByteString.copyFrom(new byte[] {(byte) 0x80}))
                                .setOutputPrefixType(OutputPrefixType.RAW)))
                .build());
    assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
  }

  @Test
  public void parseParameters_invalidSerializations_badOutputPrefixType_throws() throws Exception {
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
            OutputPrefixType.UNKNOWN_PREFIX,
            PrfBasedDeriverKeyFormat.newBuilder()
                .setPrfKeyTemplate(
                    KeyTemplate.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.AesCmacPrfKey")
                        .setValue(PRF_KEY_FORMAT_PROTO.toByteString())
                        .setOutputPrefixType(OutputPrefixType.TINK))
                .setParams(
                    PrfBasedDeriverParams.newBuilder()
                        .setDerivedKeyTemplate(
                            KeyTemplate.newBuilder()
                                .setTypeUrl(
                                    "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key")
                                .setValue(DERIVED_KEY_FORMAT_PROTO.toByteString())
                                .setOutputPrefixType(OutputPrefixType.UNKNOWN_PREFIX)))
                .build());
    assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
  }
}
