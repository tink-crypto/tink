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

package com.google.crypto.tink.prf.internal;

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
import com.google.crypto.tink.prf.AesCmacPrfKey;
import com.google.crypto.tink.prf.AesCmacPrfParameters;
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
 * Methods to serialize and parse {@link AesCmacPrfKey} objects and {@link AesCmacPrfParameters}
 * objects.
 */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class AesCmacPrfProtoSerialization {
  private static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.AesCmacPrfKey";
  private static final Bytes TYPE_URL_BYTES = toBytesFromPrintableAscii(TYPE_URL);

  private static final ParametersSerializer<AesCmacPrfParameters, ProtoParametersSerialization>
      PARAMETERS_SERIALIZER =
          ParametersSerializer.create(
              AesCmacPrfProtoSerialization::serializeParameters,
              AesCmacPrfParameters.class,
              ProtoParametersSerialization.class);

  private static final ParametersParser<ProtoParametersSerialization> PARAMETERS_PARSER =
      ParametersParser.create(
          AesCmacPrfProtoSerialization::parseParameters,
          TYPE_URL_BYTES,
          ProtoParametersSerialization.class);

  private static final KeySerializer<AesCmacPrfKey, ProtoKeySerialization> KEY_SERIALIZER =
      KeySerializer.create(
          AesCmacPrfProtoSerialization::serializeKey,
          AesCmacPrfKey.class,
          ProtoKeySerialization.class);

  private static final KeyParser<ProtoKeySerialization> KEY_PARSER =
      KeyParser.create(
          AesCmacPrfProtoSerialization::parseKey, TYPE_URL_BYTES, ProtoKeySerialization.class);

  private static ProtoParametersSerialization serializeParameters(AesCmacPrfParameters parameters) {
    return ProtoParametersSerialization.create(
        KeyTemplate.newBuilder()
            .setTypeUrl(TYPE_URL)
            .setValue(
                com.google.crypto.tink.proto.AesCmacPrfKeyFormat.newBuilder()
                    .setKeySize(parameters.getKeySizeBytes())
                    .build()
                    .toByteString())
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build());
  }

  private static ProtoKeySerialization serializeKey(
      AesCmacPrfKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        TYPE_URL,
        com.google.crypto.tink.proto.AesCmacPrfKey.newBuilder()
            .setKeyValue(
                ByteString.copyFrom(
                    key.getKeyBytes().toByteArray(SecretKeyAccess.requireAccess(access))))
            .build()
            .toByteString(),
        KeyMaterialType.SYMMETRIC,
        OutputPrefixType.RAW,
        key.getIdRequirementOrNull());
  }

  private static AesCmacPrfParameters parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    if (!serialization.getKeyTemplate().getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to AesCmacPrfProtoSerialization.parseParameters: "
              + serialization.getKeyTemplate().getTypeUrl());
    }
    com.google.crypto.tink.proto.AesCmacPrfKeyFormat format;
    try {
      format =
          com.google.crypto.tink.proto.AesCmacPrfKeyFormat.parseFrom(
              serialization.getKeyTemplate().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing AesCmacPrfParameters failed: ", e);
    }
    if (format.getVersion() != 0) {
      throw new GeneralSecurityException(
          "Parsing AesCmacPrfParameters failed: unknown Version " + format.getVersion());
    }
    if (serialization.getKeyTemplate().getOutputPrefixType() != OutputPrefixType.RAW) {
      throw new GeneralSecurityException(
          "Parsing AesCmacPrfParameters failed: only RAW output prefix type is accepted");
    }
    return AesCmacPrfParameters.create(format.getKeySize());
  }

  @SuppressWarnings("UnusedException") // Proto parsing error adds no relevant information
  private static AesCmacPrfKey parseKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to AesCmacPrfProtoSerialization.parseKey");
    }
    try {
      com.google.crypto.tink.proto.AesCmacPrfKey protoKey =
          com.google.crypto.tink.proto.AesCmacPrfKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }
      if (serialization.getIdRequirementOrNull() != null) {
        throw new GeneralSecurityException("ID requirement must be null.");
      }
      AesCmacPrfParameters parameters = AesCmacPrfParameters.create(protoKey.getKeyValue().size());
      return AesCmacPrfKey.create(
          parameters,
          SecretBytes.copyFrom(
              protoKey.getKeyValue().toByteArray(), SecretKeyAccess.requireAccess(access)));

    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing AesCmacPrfKey failed");
    }
  }

  /**
   * Registers previously defined parser/serializer objects into a global, mutable registry.
   * Registration is public to enable custom configurations.
   */
  public static void register() throws GeneralSecurityException {
    register(MutableSerializationRegistry.globalInstance());
  }

  /** Registers previously defined parser/serializer objects into a given registry. */
  public static void register(MutableSerializationRegistry registry)
      throws GeneralSecurityException {
    registry.registerParametersSerializer(PARAMETERS_SERIALIZER);
    registry.registerParametersParser(PARAMETERS_PARSER);
    registry.registerKeySerializer(KEY_SERIALIZER);
    registry.registerKeyParser(KEY_PARSER);
  }

  private AesCmacPrfProtoSerialization() {}
}
