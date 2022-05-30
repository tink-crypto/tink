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
import com.google.errorprone.annotations.Immutable;

/**
 * Represents a {@code KeyFormat} object serialized with binary protobuf Serialization.
 *
 * <p>{@code ProtoKeyFormatSerialization} objects fully describe a {@code KeyFormat} object, but
 * tailored for protocol buffer serialization.
 */
@Immutable
public final class ProtoKeyFormatSerialization implements Serialization {
  private final ByteArray objectIdentifier;
  private final KeyTemplate keyTemplate;

  private ProtoKeyFormatSerialization(KeyTemplate keyTemplate) {
    this.keyTemplate = keyTemplate;
    this.objectIdentifier = ByteArray.copyFrom(keyTemplate.getTypeUrl().getBytes(UTF_8));
  }

  /** Creates a new {@code ProtoKeyFormatSerialization} object. */
  public static ProtoKeyFormatSerialization create(KeyTemplate keyTemplate) {
    return new ProtoKeyFormatSerialization(keyTemplate);
  }

  /** The contents of the field value in the message com.google.crypto.tink.proto.KeyData. */
  public KeyTemplate getKeyTemplate() {
    return keyTemplate;
  }

  /** The typeUrl. */
  @Override
  public ByteArray getObjectIdentifier() {
    return objectIdentifier;
  }
}
