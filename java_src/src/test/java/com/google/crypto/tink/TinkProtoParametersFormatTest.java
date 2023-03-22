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

package com.google.crypto.tink;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.internal.LegacyProtoParameters;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.mac.AesCmacParameters;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.proto.AesCmacKeyFormat;
import com.google.crypto.tink.proto.AesCmacParams;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Hex;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class TinkProtoParametersFormatTest {

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    MacConfig.register();
  }

  @Test
  public void testParseAesCmacFormat() throws GeneralSecurityException {
    AesCmacKeyFormat format =
        AesCmacKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(AesCmacParams.newBuilder().setTagSize(16))
            .build();
    KeyTemplate template =
        KeyTemplate.newBuilder()
            .setValue(format.toByteString())
            .setOutputPrefixType(OutputPrefixType.TINK)
            .setTypeUrl("type.googleapis.com/google.crypto.tink.AesCmacKey")
            .build();
    assertThat(TinkProtoParametersFormat.parse(template.toByteArray()))
        .isEqualTo(
            AesCmacParameters.builder()
                .setKeySizeBytes(32)
                .setTagSizeBytes(16)
                .setVariant(AesCmacParameters.Variant.TINK)
                .build());
  }

  @Test
  public void testParseInvalidAesCmacFormat_throws() throws GeneralSecurityException {
    AesCmacKeyFormat format =
        AesCmacKeyFormat.newBuilder()
            .setKeySize(37) // Invalid Key Size
            .setParams(AesCmacParams.newBuilder().setTagSize(16))
            .build();
    KeyTemplate template =
        KeyTemplate.newBuilder()
            .setValue(format.toByteString())
            .setOutputPrefixType(OutputPrefixType.TINK)
            .setTypeUrl("type.googleapis.com/google.crypto.tink.AesCmacKey")
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> TinkProtoParametersFormat.parse(template.toByteArray()));
  }

  @Test
  public void testSerializeAesCmacFormat() throws Exception {
    AesCmacParameters params =
        AesCmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(16)
            .setVariant(AesCmacParameters.Variant.TINK)
            .build();

    byte[] serialized = TinkProtoParametersFormat.serialize(params);

    KeyTemplate template =
        KeyTemplate.parseFrom(serialized, ExtensionRegistryLite.getEmptyRegistry());

    assertThat(template.getOutputPrefixType()).isEqualTo(OutputPrefixType.TINK);
    assertThat(template.getTypeUrl())
        .isEqualTo("type.googleapis.com/google.crypto.tink.AesCmacKey");
    assertThat(AesCmacKeyFormat.parseFrom(template.getValue()))
        .isEqualTo(
            AesCmacKeyFormat.newBuilder()
                .setKeySize(32)
                .setParams(AesCmacParams.newBuilder().setTagSize(16))
                .build());
  }

  /** When parsing, if a TypeURL is not recognized we currently always parse into a Legacy object */
  @Test
  public void testParseToLegacyFormat() throws Exception {
    KeyTemplate template =
        KeyTemplate.newBuilder()
            .setValue(ByteString.copyFrom(Hex.decode("80")))
            .setOutputPrefixType(OutputPrefixType.TINK)
            .setTypeUrl("SomeInvalidTypeURL")
            .build();
    Parameters parsed = TinkProtoParametersFormat.parse(template.toByteArray());

    LegacyProtoParameters expected =
        new LegacyProtoParameters(ProtoParametersSerialization.create(template));

    assertThat(parsed).isEqualTo(expected);
  }

  /** When serializing a legacy object, we always succeed, even if an object is registered. */
  @Test
  public void testSerializeFromLegacyFormat() throws Exception {
    KeyTemplate template =
        KeyTemplate.newBuilder()
            .setValue(ByteString.copyFrom(Hex.decode("80")))
            .setOutputPrefixType(OutputPrefixType.TINK)
            .setTypeUrl("SomeInvalidTypeURL")
            .build();
    LegacyProtoParameters legacyParameters =
        new LegacyProtoParameters(ProtoParametersSerialization.create(template));

    byte[] serialized = TinkProtoParametersFormat.serialize(legacyParameters);

    assertThat(KeyTemplate.parseFrom(serialized, ExtensionRegistryLite.getEmptyRegistry()))
        .isEqualTo(template);
  }
}
