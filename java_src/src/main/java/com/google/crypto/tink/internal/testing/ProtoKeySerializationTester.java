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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/** Helps to test ProtoKey serialization methods. */
public final class ProtoKeySerializationTester {
  private final String typeUrl;
  private final KeyMaterialType keyMaterialType;
  private final boolean requiresSecretKeyAccess;
  private final MutableSerializationRegistry serializationRegistry;

  public ProtoKeySerializationTester(
      String typeUrl, KeyMaterialType keyMaterialType, boolean requiresSecretKeyAccess) {
    this(
        typeUrl,
        keyMaterialType,
        requiresSecretKeyAccess,
        MutableSerializationRegistry.globalInstance());
  }

  public ProtoKeySerializationTester(
      String typeUrl,
      KeyMaterialType keyMaterialType,
      boolean requiresSecretKeyAccess,
      MutableSerializationRegistry serializationRegistry) {
    this.typeUrl = typeUrl;
    this.keyMaterialType = keyMaterialType;
    this.requiresSecretKeyAccess = requiresSecretKeyAccess;
    this.serializationRegistry = serializationRegistry;
  }

  /**
   * Tests whether {@link Key} is equal to the key parsed from {@code protoKey}, {@code
   * OutputPrefixType}, {@code idRequirement}, and the {@code keyMaterialType} passed in to the
   * constructor.
   */
  public void testParse(
      Key key,
      MessageLite protoKey,
      OutputPrefixType outputPrefixType,
      @Nullable Integer idRequirement)
      throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            typeUrl, protoKey.toByteString(), keyMaterialType, outputPrefixType, idRequirement);
    Key parsedKey = serializationRegistry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsedKey.equalsKey(key)).isTrue();
    if (requiresSecretKeyAccess) {
      assertThrows(
          GeneralSecurityException.class,
          () -> serializationRegistry.parseKey(serialization, null));
    } else {
      // If we don't expect to require secret key access, we also check without an access token.
      Key parsedKey2 = serializationRegistry.parseKey(serialization, null);
      assertThat(parsedKey2.equalsKey(key)).isTrue();
    }
  }

  /**
   * Tests whether the given {@link Key}, when serialized, gives a proto which is equal to the
   * given {@code protoKey}, as well as {@code outputPrefixType}, {@code idRequirement}, and {@code
   * keyMaterialType} as passed in to the constructor.
   */
  public void testSerialize(
      Key key,
      MessageLite protoKey,
      OutputPrefixType outputPrefixType,
      @Nullable Integer idRequirement)
      throws Exception {
    ProtoKeySerialization serialized =
        serializationRegistry.serializeKey(
            key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertThat(serialized.getTypeUrl()).isEqualTo(typeUrl);
    assertThat(serialized.getOutputPrefixType()).isEqualTo(outputPrefixType);
    assertThat(serialized.getIdRequirementOrNull()).isEqualTo(idRequirement);
    assertThat(serialized.getKeyMaterialType()).isEqualTo(keyMaterialType);
    MessageLite parsedKey =
        protoKey
            .getParserForType()
            .parseFrom(serialized.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(parsedKey).isEqualTo(protoKey);
    if (requiresSecretKeyAccess) {
      assertThrows(
          GeneralSecurityException.class,
          () -> serializationRegistry.serializeKey(key, ProtoKeySerialization.class, null));
    } else {
      ProtoKeySerialization serialized2 =
          serializationRegistry.serializeKey(key, ProtoKeySerialization.class, null);
      assertThat(serialized2.getTypeUrl()).isEqualTo(typeUrl);
      assertThat(serialized2.getOutputPrefixType()).isEqualTo(outputPrefixType);
      assertThat(serialized2.getIdRequirementOrNull()).isEqualTo(idRequirement);
      assertThat(serialized2.getKeyMaterialType()).isEqualTo(keyMaterialType);
      MessageLite parsedKey2 =
          protoKey
              .getParserForType()
              .parseFrom(serialized2.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      assertThat(parsedKey2).isEqualTo(protoKey);
    }
  }

  /** Runs {@link #testParse} and {#link testSerialize}. */
  public void testParseAndSerialize(
      Key key,
      MessageLite protoKey,
      OutputPrefixType outputPrefixType,
      @Nullable Integer idRequirement)
      throws Exception {
    testParse(key, protoKey, outputPrefixType, idRequirement);
    testSerialize(key, protoKey, outputPrefixType, idRequirement);
  }
}
