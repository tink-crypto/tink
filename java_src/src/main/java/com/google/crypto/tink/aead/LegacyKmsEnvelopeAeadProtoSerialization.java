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
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ParametersParser;
import com.google.crypto.tink.internal.ParametersSerializer;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.KeyTemplate;
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

  @AccessesPartialKey
  private static ProtoParametersSerialization serializeParameters(
      LegacyKmsEnvelopeAeadParameters parameters) throws GeneralSecurityException {
    byte[] serializedDekParameters =
        TinkProtoParametersFormat.serialize(parameters.getDekParametersForNewKeys());
    try {
      KeyTemplate dekKeyTemplate =
          KeyTemplate.parseFrom(serializedDekParameters, ExtensionRegistryLite.getEmptyRegistry());
      return ProtoParametersSerialization.create(
          KeyTemplate.newBuilder()
              .setTypeUrl(TYPE_URL)
              .setValue(
                  KmsEnvelopeAeadKeyFormat.newBuilder()
                      .setKekUri(parameters.getKekUri())
                      .setDekTemplate(dekKeyTemplate)
                      .build()
                      .toByteString())
              .setOutputPrefixType(OutputPrefixType.RAW)
              .build());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing KmsEnvelopeAeadKeyFormat failed: ", e);
    }
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

  public static void register() throws GeneralSecurityException {
    register(MutableSerializationRegistry.globalInstance());
  }

  public static void register(MutableSerializationRegistry registry)
      throws GeneralSecurityException {
    registry.registerParametersSerializer(PARAMETERS_SERIALIZER);
    registry.registerParametersParser(PARAMETERS_PARSER);
  }

  private LegacyKmsEnvelopeAeadProtoSerialization() {}
}
