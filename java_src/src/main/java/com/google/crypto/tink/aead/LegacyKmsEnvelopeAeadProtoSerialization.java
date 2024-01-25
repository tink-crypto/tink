// Copyright 2023 Google Inc.
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
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.internal.KeyParser;
import com.google.crypto.tink.internal.KeySerializer;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ParametersParser;
import com.google.crypto.tink.internal.ParametersSerializer;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.KmsEnvelopeAeadKey;
import com.google.crypto.tink.proto.KmsEnvelopeAeadKeyFormat;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.Bytes;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Serializers and Parsers for LegacyKmsEnvelopeAeadProtoKey and
 * LegacyKmsEnvelopeAeadProtoParameters
 */
public final class LegacyKmsEnvelopeAeadProtoSerialization {
  private static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey";
  private static final Bytes TYPE_URL_BYTES = toBytesFromPrintableAscii(TYPE_URL);

  private static final ParametersSerializer<
          LegacyKmsEnvelopeAeadParameters, ProtoParametersSerialization>
      PARAMETERS_SERIALIZER =
          ParametersSerializer.create(
              LegacyKmsEnvelopeAeadProtoSerialization::serializeParameters,
              LegacyKmsEnvelopeAeadParameters.class,
              ProtoParametersSerialization.class);

  private static final ParametersParser<ProtoParametersSerialization> PARAMETERS_PARSER =
      ParametersParser.create(
          LegacyKmsEnvelopeAeadProtoSerialization::parseParameters,
          TYPE_URL_BYTES,
          ProtoParametersSerialization.class);

  private static final KeySerializer<LegacyKmsEnvelopeAeadKey, ProtoKeySerialization>
      KEY_SERIALIZER =
          KeySerializer.create(
              LegacyKmsEnvelopeAeadProtoSerialization::serializeKey,
              LegacyKmsEnvelopeAeadKey.class,
              ProtoKeySerialization.class);

  private static final KeyParser<ProtoKeySerialization> KEY_PARSER =
      KeyParser.create(
          LegacyKmsEnvelopeAeadProtoSerialization::parseKey,
          TYPE_URL_BYTES,
          ProtoKeySerialization.class);

  @AccessesPartialKey
  private static ProtoParametersSerialization serializeParameters(
      LegacyKmsEnvelopeAeadParameters parameters) throws GeneralSecurityException {
    return ProtoParametersSerialization.create(
        KeyTemplate.newBuilder()
            .setTypeUrl(TYPE_URL)
            .setValue(serializeParametersToKmsEnvelopeAeadKeyFormat(parameters).toByteString())
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build());
  }

  @AccessesPartialKey
  private static KmsEnvelopeAeadKeyFormat serializeParametersToKmsEnvelopeAeadKeyFormat(
      LegacyKmsEnvelopeAeadParameters parameters) throws GeneralSecurityException {
    byte[] serializedDekParameters =
        TinkProtoParametersFormat.serialize(parameters.getDekParametersForNewKeys());
    try {
      KeyTemplate dekKeyTemplate =
          KeyTemplate.parseFrom(serializedDekParameters, ExtensionRegistryLite.getEmptyRegistry());
      return KmsEnvelopeAeadKeyFormat.newBuilder()
          .setKekUri(parameters.getKekUri())
          .setDekTemplate(dekKeyTemplate)
          .build();
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing KmsEnvelopeAeadKeyFormat failed: ", e);
    }
  }

  @AccessesPartialKey
  private static ProtoKeySerialization serializeKey(
      LegacyKmsEnvelopeAeadKey key, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        TYPE_URL,
        KmsEnvelopeAeadKey.newBuilder()
            .setParams(serializeParametersToKmsEnvelopeAeadKeyFormat(key.getParameters()))
            .build()
            .toByteString(),
        KeyMaterialType.REMOTE,
        OutputPrefixType.RAW,
        key.getIdRequirementOrNull());
  }

  @AccessesPartialKey
  private static LegacyKmsEnvelopeAeadParameters parseParameters(
      ProtoParametersSerialization serialization) throws GeneralSecurityException {
    if (!serialization.getKeyTemplate().getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to LegacyKmsEnvelopeAeadProtoSerialization.parseParameters: "
              + serialization.getKeyTemplate().getTypeUrl());
    }
    KmsEnvelopeAeadKeyFormat format;
    try {
      format =
          KmsEnvelopeAeadKeyFormat.parseFrom(
              serialization.getKeyTemplate().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing KmsEnvelopeAeadKeyFormat failed: ", e);
    }
    return parseParameters(format);
  }

  @AccessesPartialKey
  private static LegacyKmsEnvelopeAeadParameters parseParameters(KmsEnvelopeAeadKeyFormat format)
      throws GeneralSecurityException {
    Parameters aeadParameters =
        TinkProtoParametersFormat.parse(
            KeyTemplate.newBuilder()
                .setTypeUrl(format.getDekTemplate().getTypeUrl())
                .setValue(format.getDekTemplate().getValue())
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build()
                .toByteArray());

    @Nullable LegacyKmsEnvelopeAeadParameters.DekParsingStrategy strategy;

    if (aeadParameters instanceof AesGcmParameters) {
      strategy = LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_GCM;
    } else if (aeadParameters instanceof ChaCha20Poly1305Parameters) {
      strategy = LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_CHACHA20POLY1305;
    } else if (aeadParameters instanceof XChaCha20Poly1305Parameters) {
      strategy = LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_XCHACHA20POLY1305;
    } else if (aeadParameters instanceof AesCtrHmacAeadParameters) {
      strategy = LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_CTR_HMAC;
    } else if (aeadParameters instanceof AesEaxParameters) {
      strategy = LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_EAX;
    } else if (aeadParameters instanceof AesGcmSivParameters) {
      strategy = LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_GCM_SIV;
    } else {
      throw new GeneralSecurityException(
          "Unsupported DEK parameters when parsing " + aeadParameters);
    }
    return LegacyKmsEnvelopeAeadParameters.builder()
        .setKekUri(format.getKekUri())
        .setDekParametersForNewKeys((AeadParameters) aeadParameters)
        .setDekParsingStrategy(strategy)
        .build();
  }

  @AccessesPartialKey
  private static LegacyKmsEnvelopeAeadKey parseKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to LegacyKmsEnvelopeAeadProtoSerialization.parseKey");
    }
    try {
      KmsEnvelopeAeadKey protoKey =
          KmsEnvelopeAeadKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (serialization.getOutputPrefixType() != OutputPrefixType.RAW) {
        throw new GeneralSecurityException(
            "KmsEnvelopeAeadKeys are only accepted with OutputPrefixType RAW, got " + protoKey);
      }
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException(
            "KmsEnvelopeAeadKeys are only accepted with version 0, got " + protoKey);
      }

      LegacyKmsEnvelopeAeadParameters parameters = parseParameters(protoKey.getParams());
      return LegacyKmsEnvelopeAeadKey.create(parameters);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing KmsEnvelopeAeadKey failed: ", e);
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

  private LegacyKmsEnvelopeAeadProtoSerialization() {}
}
