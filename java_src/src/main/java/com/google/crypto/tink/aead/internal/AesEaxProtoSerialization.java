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

package com.google.crypto.tink.aead.internal;

import static com.google.crypto.tink.internal.Util.toBytesFromPrintableAscii;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.aead.AesEaxKey;
import com.google.crypto.tink.aead.AesEaxParameters;
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

/** Methods to serialize and parse {@link AesEaxKey} objects and {@link AesEaxParameters} objects */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class AesEaxProtoSerialization {
  private static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.AesEaxKey";
  private static final Bytes TYPE_URL_BYTES = toBytesFromPrintableAscii(TYPE_URL);

  private static final ParametersSerializer<AesEaxParameters, ProtoParametersSerialization>
      PARAMETERS_SERIALIZER =
          ParametersSerializer.create(
              AesEaxProtoSerialization::serializeParameters,
              AesEaxParameters.class,
              ProtoParametersSerialization.class);

  private static final ParametersParser<ProtoParametersSerialization> PARAMETERS_PARSER =
      ParametersParser.create(
          AesEaxProtoSerialization::parseParameters,
          TYPE_URL_BYTES,
          ProtoParametersSerialization.class);

  private static final KeySerializer<AesEaxKey, ProtoKeySerialization> KEY_SERIALIZER =
      KeySerializer.create(
          AesEaxProtoSerialization::serializeKey, AesEaxKey.class, ProtoKeySerialization.class);

  private static final KeyParser<ProtoKeySerialization> KEY_PARSER =
      KeyParser.create(
          AesEaxProtoSerialization::parseKey, TYPE_URL_BYTES, ProtoKeySerialization.class);

  private static OutputPrefixType toProtoOutputPrefixType(AesEaxParameters.Variant variant)
      throws GeneralSecurityException {
    if (AesEaxParameters.Variant.TINK.equals(variant)) {
      return OutputPrefixType.TINK;
    }
    if (AesEaxParameters.Variant.CRUNCHY.equals(variant)) {
      return OutputPrefixType.CRUNCHY;
    }
    if (AesEaxParameters.Variant.NO_PREFIX.equals(variant)) {
      return OutputPrefixType.RAW;
    }
    throw new GeneralSecurityException("Unable to serialize variant: " + variant);
  }

  private static AesEaxParameters.Variant toVariant(OutputPrefixType outputPrefixType)
      throws GeneralSecurityException {
    switch (outputPrefixType) {
      case TINK:
        return AesEaxParameters.Variant.TINK;
        /** Parse LEGACY prefix to CRUNCHY, since they act the same for this type of key */
      case CRUNCHY:
      case LEGACY:
        return AesEaxParameters.Variant.CRUNCHY;
      case RAW:
        return AesEaxParameters.Variant.NO_PREFIX;
      default:
        throw new GeneralSecurityException(
            "Unable to parse OutputPrefixType: " + outputPrefixType.getNumber());
    }
  }

  private static com.google.crypto.tink.proto.AesEaxParams getProtoParams(
      AesEaxParameters parameters) throws GeneralSecurityException {
    /** Current implementation restricts to 16-byte tag value */
    if (parameters.getTagSizeBytes() != 16) {
      throw new GeneralSecurityException(
          String.format(
              "Invalid tag size in bytes %d. Currently Tink only supports aes eax keys with tag"
                  + " size equal to 16 bytes.",
              parameters.getTagSizeBytes()));
    }
    return com.google.crypto.tink.proto.AesEaxParams.newBuilder()
        .setIvSize(parameters.getIvSizeBytes())
        .build();
  }

  private static ProtoParametersSerialization serializeParameters(AesEaxParameters parameters)
      throws GeneralSecurityException {
    return ProtoParametersSerialization.create(
        KeyTemplate.newBuilder()
            .setTypeUrl(TYPE_URL)
            .setValue(
                com.google.crypto.tink.proto.AesEaxKeyFormat.newBuilder()
                    .setParams(getProtoParams(parameters))
                    .setKeySize(parameters.getKeySizeBytes())
                    .build()
                    .toByteString())
            .setOutputPrefixType(toProtoOutputPrefixType(parameters.getVariant()))
            .build());
  }

  private static ProtoKeySerialization serializeKey(AesEaxKey key, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        TYPE_URL,
        com.google.crypto.tink.proto.AesEaxKey.newBuilder()
            .setParams(getProtoParams(key.getParameters()))
            .setKeyValue(
                ByteString.copyFrom(
                    key.getKeyBytes().toByteArray(SecretKeyAccess.requireAccess(access))))
            .build()
            .toByteString(),
        KeyMaterialType.SYMMETRIC,
        toProtoOutputPrefixType(key.getParameters().getVariant()),
        key.getIdRequirementOrNull());
  }

  private static AesEaxParameters parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    if (!serialization.getKeyTemplate().getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to AesEaxProtoSerialization.parseParameters: "
              + serialization.getKeyTemplate().getTypeUrl());
    }
    com.google.crypto.tink.proto.AesEaxKeyFormat format;
    try {
      format =
          com.google.crypto.tink.proto.AesEaxKeyFormat.parseFrom(
              serialization.getKeyTemplate().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing AesEaxParameters failed: ", e);
    }
    return AesEaxParameters.builder()
        .setKeySizeBytes(format.getKeySize())
        .setIvSizeBytes(format.getParams().getIvSize())
        /** Subtle implementation currently restricts tag size to 16 bytes. */
        .setTagSizeBytes(16)
        .setVariant(toVariant(serialization.getKeyTemplate().getOutputPrefixType()))
        .build();
  }

  @SuppressWarnings("UnusedException")
  private static AesEaxKey parseKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to AesEaxProtoSerialization.parseKey");
    }
    try {
      com.google.crypto.tink.proto.AesEaxKey protoKey =
          com.google.crypto.tink.proto.AesEaxKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }
      AesEaxParameters parameters =
          AesEaxParameters.builder()
              .setKeySizeBytes(protoKey.getKeyValue().size())
              .setIvSizeBytes(protoKey.getParams().getIvSize())
              .setTagSizeBytes(16)
              .setVariant(toVariant(serialization.getOutputPrefixType()))
              .build();
      return AesEaxKey.builder()
          .setParameters(parameters)
          .setKeyBytes(
              SecretBytes.copyFrom(
                  protoKey.getKeyValue().toByteArray(), SecretKeyAccess.requireAccess(access)))
          .setIdRequirement(serialization.getIdRequirementOrNull())
          .build();
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing AesEaxcKey failed");
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

  private AesEaxProtoSerialization() {}
}
