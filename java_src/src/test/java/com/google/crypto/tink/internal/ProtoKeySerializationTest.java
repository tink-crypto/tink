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

package com.google.crypto.tink.internal;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.Bytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@code ProtoKeySerialization} */
@RunWith(JUnit4.class)
public final class ProtoKeySerializationTest {
  @Test
  public void testCreationAndValues_basic() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "myTypeUrl",
            ByteString.copyFrom(new byte[] {10, 11, 12}),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement = */ null);

    assertThat(serialization.getValue()).isEqualTo(ByteString.copyFrom(new byte[] {10, 11, 12}));
    assertThat(serialization.getKeyMaterialType()).isEqualTo(KeyMaterialType.SYMMETRIC);
    assertThat(serialization.getOutputPrefixType()).isEqualTo(OutputPrefixType.RAW);
    assertThat(serialization.getTypeUrl()).isEqualTo("myTypeUrl");
    assertThat(serialization.getIdRequirementOrNull()).isNull();
    assertThat(serialization.getObjectIdentifier())
        .isEqualTo(Bytes.copyFrom("myTypeUrl".getBytes(UTF_8)));
  }

  @Test
  public void testIdRequirement_present() throws Exception {
    final String typeUrl = "myTypeUrl";
    final ByteString value = ByteString.copyFrom(new byte[] {10, 11, 12});
    final KeyMaterialType keyMaterialType = KeyMaterialType.SYMMETRIC;

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(typeUrl, value, keyMaterialType, OutputPrefixType.TINK, 123);
    assertThat(serialization.getOutputPrefixType()).isEqualTo(OutputPrefixType.TINK);
    assertThat(serialization.getIdRequirementOrNull()).isEqualTo(123);
  }

  @Test
  public void testIdRequirement_presentMustMatchoutputPrefixType() throws Exception {
    final String typeUrl = "myTypeUrl";
    final ByteString value = ByteString.copyFrom(new byte[] {10, 11, 12});
    final KeyMaterialType keyMaterialType = KeyMaterialType.SYMMETRIC;

    ProtoKeySerialization.create(
        typeUrl, value, keyMaterialType, OutputPrefixType.RAW, /* idRequirement = */ null);
    ProtoKeySerialization.create(typeUrl, value, keyMaterialType, OutputPrefixType.TINK, 123);
    ProtoKeySerialization.create(typeUrl, value, keyMaterialType, OutputPrefixType.CRUNCHY, 123);
    ProtoKeySerialization.create(typeUrl, value, keyMaterialType, OutputPrefixType.LEGACY, 123);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            ProtoKeySerialization.create(
                typeUrl, value, keyMaterialType, OutputPrefixType.RAW, 123));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            ProtoKeySerialization.create(
                typeUrl,
                value,
                keyMaterialType,
                OutputPrefixType.TINK,
                /* idRequirement = */ null));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            ProtoKeySerialization.create(
                typeUrl,
                value,
                keyMaterialType,
                OutputPrefixType.CRUNCHY,
                /* idRequirement = */ null));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            ProtoKeySerialization.create(
                typeUrl,
                value,
                keyMaterialType,
                OutputPrefixType.LEGACY,
                /* idRequirement = */ null));
  }
}
