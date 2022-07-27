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

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.MessageLite;

/**
 * Represents a {@code Parameters} object serialized with binary protobuf Serialization.
 *
 * <p>{@code ProtoParametersSerialization} objects fully describe a {@code Parameters} object, but
 * tailored for protocol buffer serialization.
 */
@Immutable
public final class ProtoParametersSerialization implements Serialization {
  private final Bytes objectIdentifier;
  private final KeyTemplate keyTemplate;

  private ProtoParametersSerialization(KeyTemplate keyTemplate) {
    this.keyTemplate = keyTemplate;
    this.objectIdentifier = Bytes.copyFrom(keyTemplate.getTypeUrl().getBytes(UTF_8));
  }

  /** Creates a new {@code ProtoParametersSerialization} object from the individual parts. */
  public static ProtoParametersSerialization create(
      String typeUrl, OutputPrefixType outputPrefixType, MessageLite value) {
    return create(
        KeyTemplate.newBuilder()
            .setTypeUrl(typeUrl)
            .setOutputPrefixType(outputPrefixType)
            .setValue(value.toByteString())
            .build());
  }

  /** Creates a new {@code ProtoParametersSerialization} object. */
  public static ProtoParametersSerialization create(KeyTemplate keyTemplate) {
    return new ProtoParametersSerialization(keyTemplate);
  }

  /** The contents of the field value in the message com.google.crypto.tink.proto.KeyData. */
  public KeyTemplate getKeyTemplate() {
    return keyTemplate;
  }

  /** The typeUrl. */
  @Override
  public Bytes getObjectIdentifier() {
    return objectIdentifier;
  }
}
