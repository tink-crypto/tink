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

import static com.google.crypto.tink.internal.Util.toBytesFromPrintableAscii;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.internal.KeyParser;
import com.google.crypto.tink.internal.KeySerializer;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ParametersParser;
import com.google.crypto.tink.internal.ParametersSerializer;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Methods to serialize and parse {@link ChaCha20Poly1305Key} objects and {@link
 * ChaCha20Poly1305Parameters} objects
 */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
final class ChaCha20Poly1305ProtoSerialization {
  private static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key";
  private static final Bytes TYPE_URL_BYTES = toBytesFromPrintableAscii(TYPE_URL);

  private static final ParametersSerializer<
          ChaCha20Poly1305Parameters, ProtoParametersSerialization>
      PARAMETERS_SERIALIZER =
          ParametersSerializer.create(
              ChaCha20Poly1305ProtoSerialization::serializeParameters,
              ChaCha20Poly1305Parameters.class,
              ProtoParametersSerialization.class);

  private static final ParametersParser<ProtoParametersSerialization> PARAMETERS_PARSER =
      ParametersParser.create(
          ChaCha20Poly1305ProtoSerialization::parseParameters,
          TYPE_URL_BYTES,
          ProtoParametersSerialization.class);

  private static final KeySerializer<ChaCha20Poly1305Key, ProtoKeySerialization> KEY_SERIALIZER =
      KeySerializer.create(
          ChaCha20Poly1305ProtoSerialization::serializeKey,
          ChaCha20Poly1305Key.class,
          ProtoKeySerialization.class);

  private static final KeyParser<ProtoKeySerialization> KEY_PARSER =
      KeyParser.create(
          ChaCha20Poly1305ProtoSerialization::parseKey,
          TYPE_URL_BYTES,
          ProtoKeySerialization.class);

  private static OutputPrefixType toProtoOutputPrefixType(
      ChaCha20Poly1305Parameters.Variant variant) throws GeneralSecurityException {
    if (ChaCha20Poly1305Parameters.Variant.TINK.equals(variant)) {
      return OutputPrefixType.TINK;
    }
    if (ChaCha20Poly1305Parameters.Variant.CRUNCHY.equals(variant)) {
      return OutputPrefixType.CRUNCHY;
    }
    if (ChaCha20Poly1305Parameters.Variant.NO_PREFIX.equals(variant)) {
      return OutputPrefixType.RAW;
    }
    throw new GeneralSecurityException("Unable to serialize variant: " + variant);
  }

  private static ChaCha20Poly1305Parameters.Variant toVariant(OutputPrefixType outputPrefixType)
      throws GeneralSecurityException {
    switch (outputPrefixType) {
      case TINK:
        return ChaCha20Poly1305Parameters.Variant.TINK;
        /** Parse LEGACY prefix to CRUNCHY, since they act the same for this type of key */
      case CRUNCHY:
      case LEGACY:
        return ChaCha20Poly1305Parameters.Variant.CRUNCHY;
      case RAW:
        return ChaCha20Poly1305Parameters.Variant.NO_PREFIX;
      default:
        throw new GeneralSecurityException(
            "Unable to parse OutputPrefixType: " + outputPrefixType.getNumber());
    }
  }

  private static ProtoParametersSerialization serializeParameters(
      ChaCha20Poly1305Parameters parameters) throws GeneralSecurityException {
    return ProtoParametersSerialization.create(
        KeyTemplate.newBuilder()
            .setTypeUrl(TYPE_URL)
            .setValue(
                com.google.crypto.tink.proto.ChaCha20Poly1305KeyFormat.getDefaultInstance()
                    .toByteString())
            .setOutputPrefixType(toProtoOutputPrefixType(parameters.getVariant()))
            .build());
  }

  private static ProtoKeySerialization serializeKey(
      ChaCha20Poly1305Key key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        TYPE_URL,
        com.google.crypto.tink.proto.ChaCha20Poly1305Key.newBuilder()
            .setKeyValue(
                ByteString.copyFrom(
                    key.getKeyBytes().toByteArray(SecretKeyAccess.requireAccess(access))))
            .build()
            .toByteString(),
        KeyMaterialType.SYMMETRIC,
        toProtoOutputPrefixType(key.getParameters().getVariant()),
        key.getIdRequirementOrNull());
  }

  private static ChaCha20Poly1305Parameters parseParameters(
      ProtoParametersSerialization serialization) throws GeneralSecurityException {
    if (!serialization.getKeyTemplate().getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to ChaCha20Poly1305Parameters.parseParameters: "
              + serialization.getKeyTemplate().getTypeUrl());
    }
    // ChaCha20Poly1305KeyFormat is currently an empty proto -- so it's not quite clear if we want
    // to even do anything here. However, we might add a version field later, so we at least check
    // that serialization.getKeyTemplate().getValue() is a proto-encoded string.
    try {
      Object unused =
          com.google.crypto.tink.proto.ChaCha20Poly1305KeyFormat.parseFrom(
              serialization.getKeyTemplate().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing ChaCha20Poly1305Parameters failed: ", e);
    }
    return ChaCha20Poly1305Parameters.create(
        toVariant(serialization.getKeyTemplate().getOutputPrefixType()));
  }

  @SuppressWarnings("UnusedException")
  private static ChaCha20Poly1305Key parseKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to ChaCha20Poly1305Parameters.parseParameters");
    }
    try {
      com.google.crypto.tink.proto.ChaCha20Poly1305Key protoKey =
          com.google.crypto.tink.proto.ChaCha20Poly1305Key.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }
      return ChaCha20Poly1305Key.create(
          toVariant(serialization.getOutputPrefixType()),
          SecretBytes.copyFrom(
              protoKey.getKeyValue().toByteArray(), SecretKeyAccess.requireAccess(access)),
          serialization.getIdRequirementOrNull());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing ChaCha20Poly1305Key failed");
    }
  }

  public static void register() throws GeneralSecurityException {
    register(MutableSerializationRegistry.globalInstance());
  }

  public static void register(MutableSerializationRegistry registry)
      throws GeneralSecurityException {
    registry.registerParametersSerializer(PARAMETERS_SERIALIZER);
    registry.registerParametersParser(PARAMETERS_PARSER);
    registry.registerKeySerializer(KEY_SERIALIZER);
    registry.registerKeyParser(KEY_PARSER);
  }

  private ChaCha20Poly1305ProtoSerialization() {}
}
