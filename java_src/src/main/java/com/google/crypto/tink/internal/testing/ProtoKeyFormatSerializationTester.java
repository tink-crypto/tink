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

package com.google.crypto.tink.internal.testing;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.KeyFormat;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeyFormatSerialization;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.MessageLite;

/** Helps testing ProtoKeyFormat serialization methods. */
public final class ProtoKeyFormatSerializationTester {
  private final String typeUrl;
  private final MutableSerializationRegistry serializationRegistry;

  public ProtoKeyFormatSerializationTester(String typeUrl) {
    this(typeUrl, MutableSerializationRegistry.globalInstance());
  }

  public ProtoKeyFormatSerializationTester(
      String typeUrl, MutableSerializationRegistry serializationRegistry) {
    this.serializationRegistry = serializationRegistry;
    this.typeUrl = typeUrl;
  }

  /**
   * Tests whether the {@code protoFormat} format, together with the given {@code OutputPrefixType},
   * when parsed, returns a {@link KeyFormat} object which is equal to the one passed in by in
   * {@code protoFormat}.
   */
  public void testParse(
      KeyFormat format, MessageLite protoFormat, OutputPrefixType outputPrefixType)
      throws Exception {
    KeyTemplate template =
        KeyTemplate.newBuilder()
            .setTypeUrl(typeUrl)
            .setOutputPrefixType(outputPrefixType)
            .setValue(protoFormat.toByteString())
            .build();
    ProtoKeyFormatSerialization serialization = ProtoKeyFormatSerialization.create(template);
    assertThat(serializationRegistry.parseKeyFormat(serialization)).isEqualTo(format);
  }

  /**
   * Tests whether the given {@link KeyFormat}, when serializing it, gives a proto which is equal to
   * the given {@code protoFormat}, and a {@code outputPrefixType} which equals the given one.
   */
  public void testSerialize(
      KeyFormat format, MessageLite protoFormat, OutputPrefixType outputPrefixType)
      throws Exception {
    ProtoKeyFormatSerialization serialized =
        serializationRegistry.serializeKeyFormat(format, ProtoKeyFormatSerialization.class);
    assertThat(serialized.getKeyTemplate().getTypeUrl()).isEqualTo(typeUrl);
    assertThat(serialized.getKeyTemplate().getOutputPrefixType()).isEqualTo(outputPrefixType);
    MessageLite parsedFormat =
        protoFormat
            .getParserForType()
            .parseFrom(
                serialized.getKeyTemplate().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(parsedFormat).isEqualTo(protoFormat);
  }

  /** Runs {@link #testParse} and {#link testSerialize}. */
  public void testParseAndSerialize(
      KeyFormat format, MessageLite protoFormat, OutputPrefixType outputPrefixType)
      throws Exception {
    testParse(format, protoFormat, outputPrefixType);
    testSerialize(format, protoFormat, outputPrefixType);
  }
}
