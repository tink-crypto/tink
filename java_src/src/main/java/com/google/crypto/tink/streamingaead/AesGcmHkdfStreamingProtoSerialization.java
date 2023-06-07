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
 * Methods to serialize and parse {@link AesGcmHkdfStreamingKey} objects and {@link
 * AesGcmHkdfStreamingParameters} objects
 */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
final class AesGcmHkdfStreamingProtoSerialization {
  private static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey";
  private static final Bytes TYPE_URL_BYTES = toBytesFromPrintableAscii(TYPE_URL);

  private static final ParametersSerializer<
          AesGcmHkdfStreamingParameters, ProtoParametersSerialization>
      PARAMETERS_SERIALIZER =
          ParametersSerializer.create(
              AesGcmHkdfStreamingProtoSerialization::serializeParameters,
              AesGcmHkdfStreamingParameters.class,
              ProtoParametersSerialization.class);

  private static final ParametersParser<ProtoParametersSerialization> PARAMETERS_PARSER =
      ParametersParser.create(
          AesGcmHkdfStreamingProtoSerialization::parseParameters,
          TYPE_URL_BYTES,
          ProtoParametersSerialization.class);

  private static final KeySerializer<AesGcmHkdfStreamingKey, ProtoKeySerialization> KEY_SERIALIZER =
      KeySerializer.create(
          AesGcmHkdfStreamingProtoSerialization::serializeKey,
          AesGcmHkdfStreamingKey.class,
          ProtoKeySerialization.class);

  private static final KeyParser<ProtoKeySerialization> KEY_PARSER =
      KeyParser.create(
          AesGcmHkdfStreamingProtoSerialization::parseKey,
          TYPE_URL_BYTES,
          ProtoKeySerialization.class);

  private static HashType toProtoHashType(AesGcmHkdfStreamingParameters.HashType hashType)
      throws GeneralSecurityException {
    if (AesGcmHkdfStreamingParameters.HashType.SHA1.equals(hashType)) {
      return HashType.SHA1;
    }
    if (AesGcmHkdfStreamingParameters.HashType.SHA256.equals(hashType)) {
      return HashType.SHA256;
    }
    if (AesGcmHkdfStreamingParameters.HashType.SHA512.equals(hashType)) {
      return HashType.SHA512;
    }
    throw new GeneralSecurityException("Unable to serialize HashType " + hashType);
  }

  private static AesGcmHkdfStreamingParameters.HashType toHashType(HashType hashType)
      throws GeneralSecurityException {
    switch (hashType) {
      case SHA1:
        return AesGcmHkdfStreamingParameters.HashType.SHA1;
      case SHA256:
        return AesGcmHkdfStreamingParameters.HashType.SHA256;
      case SHA512:
        return AesGcmHkdfStreamingParameters.HashType.SHA512;
      default:
        throw new GeneralSecurityException(
            "Unable to parse HashType: " + hashType.getNumber());
    }
  }

  private static com.google.crypto.tink.proto.AesGcmHkdfStreamingParams toProtoParams(
      AesGcmHkdfStreamingParameters parameters) throws GeneralSecurityException {
    return com.google.crypto.tink.proto.AesGcmHkdfStreamingParams.newBuilder()
        .setCiphertextSegmentSize(parameters.getCiphertextSegmentSizeBytes())
        .setDerivedKeySize(parameters.getDerivedAesGcmKeySizeBytes())
        .setHkdfHashType(toProtoHashType(parameters.getHkdfHashType()))
        .build();
  }

  private static ProtoParametersSerialization serializeParameters(
      AesGcmHkdfStreamingParameters parameters) throws GeneralSecurityException {
    return ProtoParametersSerialization.create(
        KeyTemplate.newBuilder()
            .setTypeUrl(TYPE_URL)
            .setValue(
                com.google.crypto.tink.proto.AesGcmHkdfStreamingKeyFormat.newBuilder()
                    .setKeySize(parameters.getKeySizeBytes())
                    .setParams(toProtoParams(parameters))
                    .build()
                    .toByteString())
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build());
  }

  private static ProtoKeySerialization serializeKey(
      AesGcmHkdfStreamingKey key, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        TYPE_URL,
        com.google.crypto.tink.proto.AesGcmHkdfStreamingKey.newBuilder()
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

  private static AesGcmHkdfStreamingParameters toParametersObject(
      com.google.crypto.tink.proto.AesGcmHkdfStreamingParams params, int keySize)
      throws GeneralSecurityException {
    return AesGcmHkdfStreamingParameters.builder()
        .setKeySizeBytes(keySize)
        .setDerivedAesGcmKeySizeBytes(params.getDerivedKeySize())
        .setCiphertextSegmentSizeBytes(params.getCiphertextSegmentSize())
        .setHkdfHashType(toHashType(params.getHkdfHashType()))
        .build();
  }

  private static AesGcmHkdfStreamingParameters parseParameters(
      ProtoParametersSerialization serialization) throws GeneralSecurityException {
    if (!serialization.getKeyTemplate().getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to AesGcmHkdfStreamingParameters.parseParameters: "
              + serialization.getKeyTemplate().getTypeUrl());
    }
    com.google.crypto.tink.proto.AesGcmHkdfStreamingKeyFormat format;
    try {
      format =
          com.google.crypto.tink.proto.AesGcmHkdfStreamingKeyFormat.parseFrom(
              serialization.getKeyTemplate().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing AesGcmHkdfStreamingParameters failed: ", e);
    }
    if (format.getVersion() != 0) {
      throw new GeneralSecurityException("Only version 0 parameters are accepted");
    }
    return toParametersObject(format.getParams(), format.getKeySize());
  }

  @SuppressWarnings("UnusedException")
  private static AesGcmHkdfStreamingKey parseKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to AesGcmHkdfStreamingParameters.parseParameters");
    }
    try {
      com.google.crypto.tink.proto.AesGcmHkdfStreamingKey protoKey =
          com.google.crypto.tink.proto.AesGcmHkdfStreamingKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }
      AesGcmHkdfStreamingParameters parameters =
          toParametersObject(protoKey.getParams(), protoKey.getKeyValue().size());
      return AesGcmHkdfStreamingKey.create(
          parameters,
          SecretBytes.copyFrom(
              protoKey.getKeyValue().toByteArray(), SecretKeyAccess.requireAccess(access)));
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing AesGcmHkdfStreamingKey failed");
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

  private AesGcmHkdfStreamingProtoSerialization() {}
}
