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

import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Optional;

/**
 * * Represents a {@code Key} object serialized with binary protobuf Serialization.
 *
 * <p>{@code ProtoKeySerialization} objects fully describe a {@code Key} object, but tailored for
 * protocol buffer serialization.
 */
@Immutable
public final class ProtoKeySerialization implements Serialization {
  private final String typeUrl;
  private final Bytes objectIdentifier;
  private final ByteString value;
  private final KeyMaterialType keyMaterialType;
  private final OutputPrefixType outputPrefixType;
  private final Optional<Integer> idRequirement;

  private ProtoKeySerialization(
      String typeUrl,
      ByteString value,
      KeyMaterialType keyMaterialType,
      OutputPrefixType outputPrefixType,
      Optional<Integer> idRequirement) {
    this.typeUrl = typeUrl;
    this.objectIdentifier = Bytes.copyFrom(typeUrl.getBytes(UTF_8));
    this.value = value;
    this.keyMaterialType = keyMaterialType;
    this.outputPrefixType = outputPrefixType;
    this.idRequirement = idRequirement;
  }

  public static ProtoKeySerialization create(
      String typeUrl,
      ByteString value,
      KeyMaterialType keyMaterialType,
      OutputPrefixType outputPrefixType,
      Optional<Integer> idRequirement)
      throws GeneralSecurityException {
    if (outputPrefixType == OutputPrefixType.RAW) {
      if (idRequirement.isPresent()) {
        throw new GeneralSecurityException(
            "Keys with output prefix type raw should not have an id requirement.");
      }
    } else {
      if (!idRequirement.isPresent()) {
        throw new GeneralSecurityException(
            "Keys with output prefix type different from raw should have an id requirement.");
      }
    }
    return new ProtoKeySerialization(
        typeUrl, value, keyMaterialType, outputPrefixType, idRequirement);
  }

  /** The contents of the field value in the message com.google.crypto.tink.proto.KeyData. */
  public ByteString getValue() {
    return value;
  }

  /**
   * The contents of the field key_material_type in the message
   * com.google.crypto.tink.proto.KeyData.
   */
  public KeyMaterialType getKeyMaterialType() {
    return keyMaterialType;
  }

  /**
   * The contents of the field output_prefix_type in the message
   * com.google.crypto.tink.proto.Keyset.Key.
   */
  public OutputPrefixType getOutputPrefixType() {
    return outputPrefixType;
  }

  /**
   * The id requirement of this key. Guaranteed to be empty if getOutputPrefixType == RAW, otherwise
   * present, and equal to the ID this key has to have.
   */
  public Optional<Integer> getIdRequirement() {
    return idRequirement;
  }

  /**
   * The object identifier.
   *
   * <p>This is the UTF8 encoding of the result of "getTypeUrl".
   */
  @Override
  public Bytes getObjectIdentifier() {
    return objectIdentifier;
  }

  /** The typeUrl. */
  public String getTypeUrl() {
    return typeUrl;
  }
}
