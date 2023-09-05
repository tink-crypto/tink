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
import com.google.crypto.tink.proto.KmsAeadKeyFormat;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.Bytes;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/** Serializers and Parsers for LegacyKmsAeadProtoKey and LegacyKmsAeadProtoParameters */
final class LegacyKmsAeadProtoSerialization {
  private static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.KmsAeadKey";
  private static final Bytes TYPE_URL_BYTES = toBytesFromPrintableAscii(TYPE_URL);

  private static final ParametersSerializer<LegacyKmsAeadParameters, ProtoParametersSerialization>
      PARAMETERS_SERIALIZER =
          ParametersSerializer.create(
              LegacyKmsAeadProtoSerialization::serializeParameters,
              LegacyKmsAeadParameters.class,
              ProtoParametersSerialization.class);

  private static final ParametersParser<ProtoParametersSerialization> PARAMETERS_PARSER =
      ParametersParser.create(
          LegacyKmsAeadProtoSerialization::parseParameters,
          TYPE_URL_BYTES,
          ProtoParametersSerialization.class);

  private static final KeySerializer<LegacyKmsAeadKey, ProtoKeySerialization> KEY_SERIALIZER =
      KeySerializer.create(
          LegacyKmsAeadProtoSerialization::serializeKey,
          LegacyKmsAeadKey.class,
          ProtoKeySerialization.class);

  private static final KeyParser<ProtoKeySerialization> KEY_PARSER =
      KeyParser.create(
          LegacyKmsAeadProtoSerialization::parseKey, TYPE_URL_BYTES, ProtoKeySerialization.class);

  private static ProtoParametersSerialization serializeParameters(
      LegacyKmsAeadParameters parameters) throws GeneralSecurityException {
    return ProtoParametersSerialization.create(
        KeyTemplate.newBuilder()
            .setTypeUrl(TYPE_URL)
            .setValue(
                KmsAeadKeyFormat.newBuilder().setKeyUri(parameters.keyUri()).build().toByteString())
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build());
  }

  private static LegacyKmsAeadParameters parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    if (!serialization.getKeyTemplate().getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to LegacyKmsAeadProtoSerialization.parseParameters: "
              + serialization.getKeyTemplate().getTypeUrl());
    }
    KmsAeadKeyFormat format;
    try {
      format =
          KmsAeadKeyFormat.parseFrom(
              serialization.getKeyTemplate().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing KmsAeadKeyFormat failed: ", e);
    }
    if (serialization.getKeyTemplate().getOutputPrefixType() != OutputPrefixType.RAW) {
      throw new GeneralSecurityException(
          "Only key templates with RAW are accepted, but got "
              + serialization.getKeyTemplate().getOutputPrefixType()
              + " with format "
              + format);
    }
    return LegacyKmsAeadParameters.create(format.getKeyUri());
  }

  private static ProtoKeySerialization serializeKey(
      LegacyKmsAeadKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        TYPE_URL,
        com.google.crypto.tink.proto.KmsAeadKey.newBuilder()
            .setParams(
                KmsAeadKeyFormat.newBuilder().setKeyUri(key.getParameters().keyUri()).build())
            .build()
            .toByteString(),
        KeyMaterialType.REMOTE,
        OutputPrefixType.RAW,
        key.getIdRequirementOrNull());
  }

  private static LegacyKmsAeadKey parseKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to LegacyKmsAeadProtoSerialization.parseKey");
    }
    if (serialization.getOutputPrefixType() != OutputPrefixType.RAW) {
      throw new GeneralSecurityException(
          "KmsAeadKey are only accepted with RAW, got " + serialization.getOutputPrefixType());
    }
    try {
      com.google.crypto.tink.proto.KmsAeadKey protoKey =
          com.google.crypto.tink.proto.KmsAeadKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException(
            "KmsAeadKey are only accepted with version 0, got " + protoKey);
      }
      LegacyKmsAeadParameters parameters =
          LegacyKmsAeadParameters.create(protoKey.getParams().getKeyUri());
      return LegacyKmsAeadKey.create(parameters);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing KmsAeadKey failed: ", e);
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

  private LegacyKmsAeadProtoSerialization() {}
}
