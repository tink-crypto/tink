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

package com.google.crypto.tink.keyderivation;

import static com.google.crypto.tink.internal.Util.toBytesFromPrintableAscii;

import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ParametersParser;
import com.google.crypto.tink.internal.ParametersSerializer;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.prf.PrfParameters;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.PrfBasedDeriverKeyFormat;
import com.google.crypto.tink.proto.PrfBasedDeriverParams;
import com.google.crypto.tink.util.Bytes;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/**
 * Methods to serialize and parse {@link PrfBasedKeyDerivationKey} and {@link
 * PrfBasedKeyDerivationParameters} objects.
 */
final class PrfBasedKeyDerivationKeyProtoSerialization {
  private static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey";
  private static final Bytes TYPE_URL_BYTES = toBytesFromPrintableAscii(TYPE_URL);

  private static final ParametersSerializer<
          PrfBasedKeyDerivationParameters, ProtoParametersSerialization>
      PARAMETERS_SERIALIZER =
          ParametersSerializer.create(
              PrfBasedKeyDerivationKeyProtoSerialization::serializeParameters,
              PrfBasedKeyDerivationParameters.class,
              ProtoParametersSerialization.class);

  private static final ParametersParser<ProtoParametersSerialization> PARAMETERS_PARSER =
      ParametersParser.create(
          PrfBasedKeyDerivationKeyProtoSerialization::parseParameters,
          TYPE_URL_BYTES,
          ProtoParametersSerialization.class);

  private static PrfBasedKeyDerivationParameters parseParameters(
      ProtoParametersSerialization serialization) throws GeneralSecurityException {
    if (!serialization.getKeyTemplate().getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to PrfBasedKeyDerivationKeyProtoSerialization.parseParameters: "
              + serialization.getKeyTemplate().getTypeUrl());
    }
    PrfBasedDeriverKeyFormat format;
    try {
      format =
          PrfBasedDeriverKeyFormat.parseFrom(
              serialization.getKeyTemplate().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing PrfBasedDeriverKeyFormat failed: ", e);
    }

    Parameters derivedKeyParameters =
        TinkProtoParametersFormat.parse(format.getParams().getDerivedKeyTemplate().toByteArray());
    Parameters prfParameters =
        TinkProtoParametersFormat.parse(format.getPrfKeyTemplate().toByteArray());
    if (!(prfParameters instanceof PrfParameters)) {
      throw new GeneralSecurityException("Non-PRF parameters stored in the field prf_key_template");
    }

    if (serialization.getKeyTemplate().getOutputPrefixType()
        != format.getParams().getDerivedKeyTemplate().getOutputPrefixType()) {
      throw new GeneralSecurityException(
          "Output-Prefix mismatch in parameters while parsing " + format);
    }

    return PrfBasedKeyDerivationParameters.builder()
        .setPrfParameters((PrfParameters) prfParameters)
        .setDerivedKeyParameters(derivedKeyParameters)
        .build();
  }

  private static ProtoParametersSerialization serializeParameters(
      PrfBasedKeyDerivationParameters parameters) throws GeneralSecurityException {
    try {
      byte[] serializedPrfParameters =
          TinkProtoParametersFormat.serialize(parameters.getPrfParameters());
      KeyTemplate prfKeyTemplate =
          KeyTemplate.parseFrom(serializedPrfParameters, ExtensionRegistryLite.getEmptyRegistry());
      byte[] serializedDerivedKeyParameters =
          TinkProtoParametersFormat.serialize(parameters.getDerivedKeyParameters());
      KeyTemplate derivedKeyTemplate =
          KeyTemplate.parseFrom(
              serializedDerivedKeyParameters, ExtensionRegistryLite.getEmptyRegistry());
      PrfBasedDeriverKeyFormat format =
          PrfBasedDeriverKeyFormat.newBuilder()
              .setPrfKeyTemplate(prfKeyTemplate)
              .setParams(
                  PrfBasedDeriverParams.newBuilder().setDerivedKeyTemplate(derivedKeyTemplate))
              .build();
      return ProtoParametersSerialization.create(
          KeyTemplate.newBuilder()
              .setTypeUrl(TYPE_URL)
              .setValue(format.toByteString())
              .setOutputPrefixType(derivedKeyTemplate.getOutputPrefixType())
              .build());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Serializing PrfBasedKeyDerivationParameters failed: ", e);
    }
  }

  public static void register() throws GeneralSecurityException {
    register(MutableSerializationRegistry.globalInstance());
  }

  public static void register(MutableSerializationRegistry registry)
      throws GeneralSecurityException {
    registry.registerParametersSerializer(PARAMETERS_SERIALIZER);
    registry.registerParametersParser(PARAMETERS_PARSER);
  }

  private PrfBasedKeyDerivationKeyProtoSerialization() {}
}
