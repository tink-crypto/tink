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

package com.google.crypto.tink.mac;

import static java.nio.charset.StandardCharsets.US_ASCII;

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
 * Methods to serialize and parse {@link AesCmacKey} objects and {@link AesCmacParameters} objects.
 */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
final class AesCmacProtoSerialization {
  private static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.AesCmacKey";
  private static final Bytes TYPE_URL_BYTES = Bytes.copyFrom(TYPE_URL.getBytes(US_ASCII));
  private static final ParametersSerializer<AesCmacParameters, ProtoParametersSerialization>
      PARAMETERS_SERIALIZER =
          ParametersSerializer.create(
              AesCmacProtoSerialization::serializeParameters,
              AesCmacParameters.class,
              ProtoParametersSerialization.class);

  private static final ParametersParser<ProtoParametersSerialization> PARAMETERS_PARSER =
      ParametersParser.create(
          AesCmacProtoSerialization::parseParameters,
          TYPE_URL_BYTES,
          ProtoParametersSerialization.class);

  private static final KeySerializer<AesCmacKey, ProtoKeySerialization> KEY_SERIALIZER =
      KeySerializer.create(
          AesCmacProtoSerialization::serializeKey, AesCmacKey.class, ProtoKeySerialization.class);

  private static final KeyParser<ProtoKeySerialization> KEY_PARSER =
      KeyParser.create(
          AesCmacProtoSerialization::parseKey, TYPE_URL_BYTES, ProtoKeySerialization.class);

  private static OutputPrefixType toOutputPrefixType(AesCmacParameters.Variant variant)
      throws GeneralSecurityException {
    if (AesCmacParameters.Variant.TINK.equals(variant)) {
      return OutputPrefixType.TINK;
    }
    if (AesCmacParameters.Variant.CRUNCHY.equals(variant)) {
      return OutputPrefixType.CRUNCHY;
    }
    if (AesCmacParameters.Variant.NO_PREFIX.equals(variant)) {
      return OutputPrefixType.RAW;
    }
    if (AesCmacParameters.Variant.LEGACY.equals(variant)) {
      return OutputPrefixType.LEGACY;
    }
    throw new GeneralSecurityException("Unable to serialize variant: " + variant);
  }

  private static AesCmacParameters.Variant toVariant(OutputPrefixType outputPrefixType)
      throws GeneralSecurityException {
    switch (outputPrefixType) {
      case TINK:
        return AesCmacParameters.Variant.TINK;
      case CRUNCHY:
        return AesCmacParameters.Variant.CRUNCHY;
      case LEGACY:
        return AesCmacParameters.Variant.LEGACY;
      case RAW:
        return AesCmacParameters.Variant.NO_PREFIX;
      default:
        throw new GeneralSecurityException(
            "Unable to parse OutputPrefixType: " + outputPrefixType.getNumber());
    }
  }

  private static com.google.crypto.tink.proto.AesCmacParams getProtoParams(
      AesCmacParameters parameters) {
    return com.google.crypto.tink.proto.AesCmacParams.newBuilder()
        .setTagSize(parameters.getCryptographicTagSizeBytes())
        .build();
  }

  private static ProtoParametersSerialization serializeParameters(AesCmacParameters parameters)
      throws GeneralSecurityException {
    return ProtoParametersSerialization.create(
        KeyTemplate.newBuilder()
            .setTypeUrl(TYPE_URL)
            .setValue(
                com.google.crypto.tink.proto.AesCmacKeyFormat.newBuilder()
                    .setParams(getProtoParams(parameters))
                    .setKeySize(32)
                    .build()
                    .toByteString())
            .setOutputPrefixType(toOutputPrefixType(parameters.getVariant()))
            .build());
  }

  private static ProtoKeySerialization serializeKey(
      AesCmacKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        TYPE_URL,
        com.google.crypto.tink.proto.AesCmacKey.newBuilder()
            .setParams(getProtoParams(key.getParameters()))
            .setKeyValue(
                ByteString.copyFrom(
                    key.getAesKey().toByteArray(SecretKeyAccess.requireAccess(access))))
            .build()
            .toByteString(),
        KeyMaterialType.SYMMETRIC,
        toOutputPrefixType(key.getParameters().getVariant()),
        key.getIdRequirementOrNull());
  }

  private static AesCmacParameters parseParams(
      com.google.crypto.tink.proto.AesCmacParams params, OutputPrefixType outputPrefixType)
      throws GeneralSecurityException {
    return AesCmacParameters.createForKeysetWithCryptographicTagSize(
        params.getTagSize(), toVariant(outputPrefixType));
  }

  private static AesCmacParameters parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    if (!serialization.getKeyTemplate().getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to AesCmacParameters.parseParameters: "
              + serialization.getKeyTemplate().getTypeUrl());
    }
    com.google.crypto.tink.proto.AesCmacKeyFormat format;
    try {
      format =
          com.google.crypto.tink.proto.AesCmacKeyFormat.parseFrom(
              serialization.getKeyTemplate().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing AesCmacParameters failed: ", e);
    }

    return parseParams(format.getParams(), serialization.getKeyTemplate().getOutputPrefixType());
  }

  @SuppressWarnings("UnusedException")
  private static AesCmacKey parseKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to AesCmacParameters.parseParameters");
    }
    try {
      com.google.crypto.tink.proto.AesCmacKey protoKey =
          com.google.crypto.tink.proto.AesCmacKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }
      AesCmacParameters parameters =
          parseParams(protoKey.getParams(), serialization.getOutputPrefixType());
      return AesCmacKey.createForKeyset(
          parameters,
          SecretBytes.copyFrom(
              protoKey.getKeyValue().toByteArray(), SecretKeyAccess.requireAccess(access)),
          serialization.getIdRequirementOrNull());
    } catch (InvalidProtocolBufferException | IllegalArgumentException e) {
      throw new GeneralSecurityException("Parsing AesCmacKey failed");
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

  private AesCmacProtoSerialization() {}
}
