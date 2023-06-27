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
import com.google.crypto.tink.proto.HashType;
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
 * Methods to serialize and parse {@link AesCtrHmacAeadKey} objects and {@link
 * AesCtrHmacAeadParameters} objects.
 */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
final class AesCtrHmacAeadProtoSerialization {
  private static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";
  private static final Bytes TYPE_URL_BYTES = toBytesFromPrintableAscii(TYPE_URL);

  private static final ParametersSerializer<AesCtrHmacAeadParameters, ProtoParametersSerialization>
      PARAMETERS_SERIALIZER =
          ParametersSerializer.create(
              AesCtrHmacAeadProtoSerialization::serializeParameters,
              AesCtrHmacAeadParameters.class,
              ProtoParametersSerialization.class);

  private static final ParametersParser<ProtoParametersSerialization> PARAMETERS_PARSER =
      ParametersParser.create(
          AesCtrHmacAeadProtoSerialization::parseParameters,
          TYPE_URL_BYTES,
          ProtoParametersSerialization.class);

  private static final KeySerializer<AesCtrHmacAeadKey, ProtoKeySerialization> KEY_SERIALIZER =
      KeySerializer.create(
          AesCtrHmacAeadProtoSerialization::serializeKey,
          AesCtrHmacAeadKey.class,
          ProtoKeySerialization.class);

  private static final KeyParser<ProtoKeySerialization> KEY_PARSER =
      KeyParser.create(
          AesCtrHmacAeadProtoSerialization::parseKey, TYPE_URL_BYTES, ProtoKeySerialization.class);

  private static OutputPrefixType toProtoOutputPrefixType(AesCtrHmacAeadParameters.Variant variant)
      throws GeneralSecurityException {
    if (AesCtrHmacAeadParameters.Variant.TINK.equals(variant)) {
      return OutputPrefixType.TINK;
    }
    if (AesCtrHmacAeadParameters.Variant.CRUNCHY.equals(variant)) {
      return OutputPrefixType.CRUNCHY;
    }
    if (AesCtrHmacAeadParameters.Variant.NO_PREFIX.equals(variant)) {
      return OutputPrefixType.RAW;
    }
    throw new GeneralSecurityException("Unable to serialize variant: " + variant);
  }

  private static AesCtrHmacAeadParameters.Variant toVariant(OutputPrefixType outputPrefixType)
      throws GeneralSecurityException {
    switch (outputPrefixType) {
      case TINK:
        return AesCtrHmacAeadParameters.Variant.TINK;
      case CRUNCHY:
      case LEGACY:
        return AesCtrHmacAeadParameters.Variant.CRUNCHY;
      case RAW:
        return AesCtrHmacAeadParameters.Variant.NO_PREFIX;
      default:
        throw new GeneralSecurityException(
            "Unable to parse OutputPrefixType: " + outputPrefixType.getNumber());
    }
  }

  private static HashType toProtoHashType(AesCtrHmacAeadParameters.HashType hashType)
      throws GeneralSecurityException {
    if (AesCtrHmacAeadParameters.HashType.SHA1.equals(hashType)) {
      return HashType.SHA1;
    }
    if (AesCtrHmacAeadParameters.HashType.SHA224.equals(hashType)) {
      return HashType.SHA224;
    }
    if (AesCtrHmacAeadParameters.HashType.SHA256.equals(hashType)) {
      return HashType.SHA256;
    }
    if (AesCtrHmacAeadParameters.HashType.SHA384.equals(hashType)) {
      return HashType.SHA384;
    }
    if (AesCtrHmacAeadParameters.HashType.SHA512.equals(hashType)) {
      return HashType.SHA512;
    }
    throw new GeneralSecurityException("Unable to serialize HashType " + hashType);
  }

  private static AesCtrHmacAeadParameters.HashType toHashType(HashType hashType)
      throws GeneralSecurityException {
    switch (hashType) {
      case SHA1:
        return AesCtrHmacAeadParameters.HashType.SHA1;
      case SHA224:
        return AesCtrHmacAeadParameters.HashType.SHA224;
      case SHA256:
        return AesCtrHmacAeadParameters.HashType.SHA256;
      case SHA384:
        return AesCtrHmacAeadParameters.HashType.SHA384;
      case SHA512:
        return AesCtrHmacAeadParameters.HashType.SHA512;
      default:
        throw new GeneralSecurityException("Unable to parse HashType: " + hashType.getNumber());
    }
  }

  private static com.google.crypto.tink.proto.HmacParams getHmacProtoParams(
      AesCtrHmacAeadParameters parameters) throws GeneralSecurityException {
    return com.google.crypto.tink.proto.HmacParams.newBuilder()
        .setTagSize(parameters.getTagSizeBytes())
        .setHash(toProtoHashType(parameters.getHashType()))
        .build();
  }

  private static ProtoParametersSerialization serializeParameters(
      AesCtrHmacAeadParameters parameters) throws GeneralSecurityException {
    return ProtoParametersSerialization.create(
        KeyTemplate.newBuilder()
            .setTypeUrl(TYPE_URL)
            .setValue(
                com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat.newBuilder()
                    .setAesCtrKeyFormat(
                        com.google.crypto.tink.proto.AesCtrKeyFormat.newBuilder()
                            .setParams(
                                com.google.crypto.tink.proto.AesCtrParams.newBuilder()
                                    .setIvSize(parameters.getIvSizeBytes())
                                    .build())
                            .setKeySize(parameters.getAesKeySizeBytes())
                            .build())
                    .setHmacKeyFormat(
                        com.google.crypto.tink.proto.HmacKeyFormat.newBuilder()
                            .setParams(getHmacProtoParams(parameters))
                            .setKeySize(parameters.getHmacKeySizeBytes())
                            .build())
                    .build()
                    .toByteString())
            .setOutputPrefixType(toProtoOutputPrefixType(parameters.getVariant()))
            .build());
  }

  private static ProtoKeySerialization serializeKey(
      AesCtrHmacAeadKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        TYPE_URL,
        com.google.crypto.tink.proto.AesCtrHmacAeadKey.newBuilder()
            .setAesCtrKey(
                com.google.crypto.tink.proto.AesCtrKey.newBuilder()
                    .setParams(
                        com.google.crypto.tink.proto.AesCtrParams.newBuilder()
                            .setIvSize(key.getParameters().getIvSizeBytes())
                            .build())
                    .setKeyValue(
                        ByteString.copyFrom(
                            key.getAesKeyBytes()
                                .toByteArray(SecretKeyAccess.requireAccess(access))))
                    .build())
            .setHmacKey(
                com.google.crypto.tink.proto.HmacKey.newBuilder()
                    .setParams(getHmacProtoParams(key.getParameters()))
                    .setKeyValue(
                        ByteString.copyFrom(
                            key.getHmacKeyBytes()
                                .toByteArray(SecretKeyAccess.requireAccess(access))))
                    .build())
            .build()
            .toByteString(),
        KeyMaterialType.SYMMETRIC,
        toProtoOutputPrefixType(key.getParameters().getVariant()),
        key.getIdRequirementOrNull());
  }

  private static AesCtrHmacAeadParameters parseParameters(
      ProtoParametersSerialization serialization) throws GeneralSecurityException {
    if (!serialization.getKeyTemplate().getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to AesCtrHmacAeadProtoSerialization.parseParameters: "
              + serialization.getKeyTemplate().getTypeUrl());
    }
    com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat format;
    try {
      format =
          com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat.parseFrom(
              serialization.getKeyTemplate().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing AesCtrHmacAeadParameters failed: ", e);
    }
    if (format.getHmacKeyFormat().getVersion() != 0) {
      throw new GeneralSecurityException("Only version 0 keys are accepted");
    }
    return AesCtrHmacAeadParameters.builder()
        .setAesKeySizeBytes(format.getAesCtrKeyFormat().getKeySize())
        .setHmacKeySizeBytes(format.getHmacKeyFormat().getKeySize())
        .setIvSizeBytes(format.getAesCtrKeyFormat().getParams().getIvSize())
        .setTagSizeBytes(format.getHmacKeyFormat().getParams().getTagSize())
        .setHashType(toHashType(format.getHmacKeyFormat().getParams().getHash()))
        .setVariant(toVariant(serialization.getKeyTemplate().getOutputPrefixType()))
        .build();
  }

  @SuppressWarnings("UnusedException")
  private static AesCtrHmacAeadKey parseKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to AesCtrHmacAeadProtoSerialization.parseKey");
    }
    try {
      com.google.crypto.tink.proto.AesCtrHmacAeadKey protoKey =
          com.google.crypto.tink.proto.AesCtrHmacAeadKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }
      if (protoKey.getAesCtrKey().getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys inner AES CTR keys are accepted");
      }
      if (protoKey.getHmacKey().getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys inner HMAC keys are accepted");
      }
      AesCtrHmacAeadParameters parameters =
          AesCtrHmacAeadParameters.builder()
              .setAesKeySizeBytes(protoKey.getAesCtrKey().getKeyValue().size())
              .setHmacKeySizeBytes(protoKey.getHmacKey().getKeyValue().size())
              .setIvSizeBytes(protoKey.getAesCtrKey().getParams().getIvSize())
              .setTagSizeBytes(protoKey.getHmacKey().getParams().getTagSize())
              .setHashType(toHashType(protoKey.getHmacKey().getParams().getHash()))
              .setVariant(toVariant(serialization.getOutputPrefixType()))
              .build();
      return AesCtrHmacAeadKey.builder()
          .setParameters(parameters)
          .setAesKeyBytes(
              SecretBytes.copyFrom(
                  protoKey.getAesCtrKey().getKeyValue().toByteArray(),
                  SecretKeyAccess.requireAccess(access)))
          .setHmacKeyBytes(
              SecretBytes.copyFrom(
                  protoKey.getHmacKey().getKeyValue().toByteArray(),
                  SecretKeyAccess.requireAccess(access)))
          .setIdRequirement(serialization.getIdRequirementOrNull())
          .build();
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing AesCtrHmacAeadKey failed");
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

  private AesCtrHmacAeadProtoSerialization() {}
}
