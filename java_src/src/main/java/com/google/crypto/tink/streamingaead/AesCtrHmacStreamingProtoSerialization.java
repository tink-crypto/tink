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

package com.google.crypto.tink.streamingaead;

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
import com.google.crypto.tink.proto.HmacParams;
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
 * Methods to serialize and parse {@link AesCtrHmacStreamingKey} objects and {@link
 * AesCtrHmacStreamingParameters} objects
 */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
final class AesCtrHmacStreamingProtoSerialization {
  private static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey";
  private static final Bytes TYPE_URL_BYTES = toBytesFromPrintableAscii(TYPE_URL);

  private static final ParametersSerializer<
          AesCtrHmacStreamingParameters, ProtoParametersSerialization>
      PARAMETERS_SERIALIZER =
          ParametersSerializer.create(
              AesCtrHmacStreamingProtoSerialization::serializeParameters,
              AesCtrHmacStreamingParameters.class,
              ProtoParametersSerialization.class);

  private static final ParametersParser<ProtoParametersSerialization> PARAMETERS_PARSER =
      ParametersParser.create(
          AesCtrHmacStreamingProtoSerialization::parseParameters,
          TYPE_URL_BYTES,
          ProtoParametersSerialization.class);

  private static final KeySerializer<AesCtrHmacStreamingKey, ProtoKeySerialization> KEY_SERIALIZER =
      KeySerializer.create(
          AesCtrHmacStreamingProtoSerialization::serializeKey,
          AesCtrHmacStreamingKey.class,
          ProtoKeySerialization.class);

  private static final KeyParser<ProtoKeySerialization> KEY_PARSER =
      KeyParser.create(
          AesCtrHmacStreamingProtoSerialization::parseKey,
          TYPE_URL_BYTES,
          ProtoKeySerialization.class);

  private static HashType toProtoHashType(AesCtrHmacStreamingParameters.HashType hashType)
      throws GeneralSecurityException {
    if (AesCtrHmacStreamingParameters.HashType.SHA1.equals(hashType)) {
      return HashType.SHA1;
    }
    if (AesCtrHmacStreamingParameters.HashType.SHA256.equals(hashType)) {
      return HashType.SHA256;
    }
    if (AesCtrHmacStreamingParameters.HashType.SHA512.equals(hashType)) {
      return HashType.SHA512;
    }
    throw new GeneralSecurityException("Unable to serialize HashType " + hashType);
  }

  private static AesCtrHmacStreamingParameters.HashType toHashType(HashType hashType)
      throws GeneralSecurityException {
    switch (hashType) {
      case SHA1:
        return AesCtrHmacStreamingParameters.HashType.SHA1;
      case SHA256:
        return AesCtrHmacStreamingParameters.HashType.SHA256;
      case SHA512:
        return AesCtrHmacStreamingParameters.HashType.SHA512;
      default:
        throw new GeneralSecurityException(
            "Unable to parse HashType: " + hashType.getNumber());
    }
  }

  private static com.google.crypto.tink.proto.AesCtrHmacStreamingParams toProtoParams(
      AesCtrHmacStreamingParameters parameters) throws GeneralSecurityException {
    return com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
        .setCiphertextSegmentSize(parameters.getCiphertextSegmentSizeBytes())
        .setDerivedKeySize(parameters.getDerivedKeySizeBytes())
        .setHkdfHashType(toProtoHashType(parameters.getHkdfHashType()))
        .setHmacParams(
            HmacParams.newBuilder()
                .setHash(toProtoHashType(parameters.getHmacHashType()))
                .setTagSize(parameters.getHmacTagSizeBytes()))
        .build();
  }

  private static ProtoParametersSerialization serializeParameters(
      AesCtrHmacStreamingParameters parameters) throws GeneralSecurityException {
    return ProtoParametersSerialization.create(
        KeyTemplate.newBuilder()
            .setTypeUrl(TYPE_URL)
            .setValue(
                com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat.newBuilder()
                    .setKeySize(parameters.getKeySizeBytes())
                    .setParams(toProtoParams(parameters))
                    .build()
                    .toByteString())
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build());
  }

  private static ProtoKeySerialization serializeKey(
      AesCtrHmacStreamingKey key, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        TYPE_URL,
        com.google.crypto.tink.proto.AesCtrHmacStreamingKey.newBuilder()
            .setKeyValue(
                ByteString.copyFrom(
                    key.getInitialKeyMaterial().toByteArray(SecretKeyAccess.requireAccess(access))))
            .setParams(toProtoParams(key.getParameters()))
            .build()
            .toByteString(),
        KeyMaterialType.SYMMETRIC,
        OutputPrefixType.RAW,
        key.getIdRequirementOrNull());
  }

  private static AesCtrHmacStreamingParameters toParametersObject(
      com.google.crypto.tink.proto.AesCtrHmacStreamingParams params, int keySize)
      throws GeneralSecurityException {
    return AesCtrHmacStreamingParameters.builder()
        .setKeySizeBytes(keySize)
        .setDerivedKeySizeBytes(params.getDerivedKeySize())
        .setCiphertextSegmentSizeBytes(params.getCiphertextSegmentSize())
        .setHkdfHashType(toHashType(params.getHkdfHashType()))
        .setHmacHashType(toHashType(params.getHmacParams().getHash()))
        .setHmacTagSizeBytes(params.getHmacParams().getTagSize())
        .build();
  }

  private static AesCtrHmacStreamingParameters parseParameters(
      ProtoParametersSerialization serialization) throws GeneralSecurityException {
    if (!serialization.getKeyTemplate().getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to AesCtrHmacStreamingParameters.parseParameters: "
              + serialization.getKeyTemplate().getTypeUrl());
    }
    com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat format;
    try {
      format =
          com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat.parseFrom(
              serialization.getKeyTemplate().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing AesCtrHmacStreamingParameters failed: ", e);
    }
    return toParametersObject(format.getParams(), format.getKeySize());
  }

  @SuppressWarnings("UnusedException")
  private static AesCtrHmacStreamingKey parseKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to AesCtrHmacStreamingParameters.parseParameters");
    }
    try {
      com.google.crypto.tink.proto.AesCtrHmacStreamingKey protoKey =
          com.google.crypto.tink.proto.AesCtrHmacStreamingKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }
      AesCtrHmacStreamingParameters parameters =
          toParametersObject(protoKey.getParams(), protoKey.getKeyValue().size());
      return AesCtrHmacStreamingKey.create(
          parameters,
          SecretBytes.copyFrom(
              protoKey.getKeyValue().toByteArray(), SecretKeyAccess.requireAccess(access)));
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing AesCtrHmacStreamingKey failed");
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

  private AesCtrHmacStreamingProtoSerialization() {}
}
