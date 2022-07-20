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

import com.google.crypto.tink.internal.ProtoKeyFormatSerialization;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import com.google.protobuf.Parser;

/** Contains static assertion functions for Tink. */
public final class Asserts {
  /**
   * Throws an assertion error if two {@link ProtoKeyFormatSerialization} objects are not equal.
   *
   * <p>Because ProtoSerialization is not deterministic, this requires a parser for the proto
   * message embedded in the {@code ProtoKeyFormatSerialization}.
   *
   * <p>Equality of the protos is decided by message equality, see {@link
   * com.google.protobuf.Message#equals}.
   */
  public static void assertEqualWhenValueParsed(
      Parser<? extends MessageLite> parser,
      ProtoKeyFormatSerialization one,
      ProtoKeyFormatSerialization two) {
    assertThat(one.getKeyTemplate().getTypeUrl()).isEqualTo(two.getKeyTemplate().getTypeUrl());
    assertThat(one.getKeyTemplate().getOutputPrefixType())
        .isEqualTo(two.getKeyTemplate().getOutputPrefixType());
    try {
      MessageLite valueOne =
          parser.parseFrom(
              one.getKeyTemplate().getValue(), ExtensionRegistryLite.getEmptyRegistry());
      MessageLite valueTwo =
          parser.parseFrom(
              two.getKeyTemplate().getValue(), ExtensionRegistryLite.getEmptyRegistry());
      assertThat(valueOne).isEqualTo(valueTwo);
    } catch (InvalidProtocolBufferException e) {
      throw new AssertionError("Unable to parse value with given parser", e);
    }
  }
  /**
   * Throws an assertion error if two {@link ProtoKeyFormatSerialization} objects are not equal.
   *
   * <p>Because ProtoSerialization is not deterministic, this requires a parser for the proto
   * message embedded in the {@code ProtoKeyFormatSerialization}.
   *
   * <p>Equality of the protos is decided by message equality, see {@link
   * com.google.protobuf.Message#equals}.
   */
  public static void assertEqualWhenValueParsed(
      Parser<? extends MessageLite> parser, ProtoKeySerialization one, ProtoKeySerialization two) {
    assertThat(one.getKeyMaterialType()).isEqualTo(two.getKeyMaterialType());
    assertThat(one.getOutputPrefixType()).isEqualTo(two.getOutputPrefixType());
    assertThat(one.getIdRequirementOrNull()).isEqualTo(two.getIdRequirementOrNull());
    assertThat(one.getTypeUrl()).isEqualTo(two.getTypeUrl());
    try {
      MessageLite valueOne =
          parser.parseFrom(one.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      MessageLite valueTwo =
          parser.parseFrom(two.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      assertThat(valueOne).isEqualTo(valueTwo);
    } catch (InvalidProtocolBufferException e) {
      throw new AssertionError("Unable to parse value with given parser", e);
    }
  }

  private Asserts() {}
}
