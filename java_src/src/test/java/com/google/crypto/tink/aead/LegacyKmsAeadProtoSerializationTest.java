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
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class LegacyKmsAeadProtoSerializationTest {
  private static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.KmsAeadKey";

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  @BeforeClass
  public static void setUp() throws Exception {
    LegacyKmsAeadProtoSerialization.register(registry);
  }

  @Test
  public void registerTwice() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    LegacyKmsAeadProtoSerialization.register(registry);
    LegacyKmsAeadProtoSerialization.register(registry);
  }

  @Test
  public void serializeParseParameters_works() throws Exception {
    LegacyKmsAeadParameters parameters = LegacyKmsAeadParameters.create("someArbitrarykeyUri723");

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.KmsAeadKeyFormat.newBuilder()
                .setKeyUri("someArbitrarykeyUri723")
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.KmsAeadKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void paramsWithInvalidOutputPrefixType_parsingFails() throws Exception {
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.KmsAeadKey",
            OutputPrefixType.TINK,
            com.google.crypto.tink.proto.KmsAeadKeyFormat.newBuilder()
                .setKeyUri("someArbitrarykeyUri723")
                .build());

    assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
  }

  @Test
  public void serializeParseKey_works() throws Exception {
    LegacyKmsAeadParameters parameters = LegacyKmsAeadParameters.create("someArbitraryKeyUri443");
    LegacyKmsAeadKey key = LegacyKmsAeadKey.create(parameters);

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.KmsAeadKey.newBuilder()
                .setParams(
                    com.google.crypto.tink.proto.KmsAeadKeyFormat.newBuilder()
                        .setKeyUri("someArbitraryKeyUri443"))
                .build()
                .toByteString(),
            KeyMaterialType.REMOTE,
            OutputPrefixType.RAW,
            null);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, null);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.KmsAeadKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, null);
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void parseKey_invalidVersion_throws() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.KmsAeadKey",
            com.google.crypto.tink.proto.KmsAeadKey.newBuilder()
                .setVersion(1)
                .setParams(
                    com.google.crypto.tink.proto.KmsAeadKeyFormat.newBuilder()
                        .setKeyUri("someArbitraryKeyUri443"))
                .build()
                .toByteString(),
            KeyMaterialType.REMOTE,
            OutputPrefixType.RAW,
            null);

    assertThrows(GeneralSecurityException.class, () -> registry.parseKey(serialization, null));
  }

  @Test
  public void parseKey_invalidOutputPrefixType_throws() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.KmsAeadKey",
            com.google.crypto.tink.proto.KmsAeadKey.newBuilder()
                .setParams(
                    com.google.crypto.tink.proto.KmsAeadKeyFormat.newBuilder()
                        .setKeyUri("someArbitraryKeyUri443"))
                .build()
                .toByteString(),
            KeyMaterialType.REMOTE,
            OutputPrefixType.TINK,
            1234);

    assertThrows(GeneralSecurityException.class, () -> registry.parseKey(serialization, null));
  }
}
