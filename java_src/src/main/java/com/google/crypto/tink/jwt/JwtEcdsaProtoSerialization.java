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

package com.google.crypto.tink.jwt;

import static com.google.crypto.tink.internal.Util.toBytesFromPrintableAscii;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ParametersParser;
import com.google.crypto.tink.internal.ParametersSerializer;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.JwtEcdsaAlgorithm;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.Bytes;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/**
 * Methods to serialize and parse {@link JwtEcdsaPrivateKey}, {@link JwtEcdsaPublicKey}, and {@link
 * JwtEcdsaParameters} objects.
 */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
final class JwtEcdsaProtoSerialization {
  private static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey";
  private static final Bytes TYPE_URL_BYTES = toBytesFromPrintableAscii(TYPE_URL);

  private static final ParametersSerializer<JwtEcdsaParameters, ProtoParametersSerialization>
      PARAMETERS_SERIALIZER =
          ParametersSerializer.create(
              JwtEcdsaProtoSerialization::serializeParameters,
              JwtEcdsaParameters.class,
              ProtoParametersSerialization.class);

  private static final ParametersParser<ProtoParametersSerialization> PARAMETERS_PARSER =
      ParametersParser.create(
          JwtEcdsaProtoSerialization::parseParameters,
          TYPE_URL_BYTES,
          ProtoParametersSerialization.class);

  private static JwtEcdsaAlgorithm toProtoAlgorithm(JwtEcdsaParameters.Algorithm algorithm)
      throws GeneralSecurityException {
    if (JwtEcdsaParameters.Algorithm.ES256.equals(algorithm)) {
      return JwtEcdsaAlgorithm.ES256;
    }
    if (JwtEcdsaParameters.Algorithm.ES384.equals(algorithm)) {
      return JwtEcdsaAlgorithm.ES384;
    }
    if (JwtEcdsaParameters.Algorithm.ES512.equals(algorithm)) {
      return JwtEcdsaAlgorithm.ES512;
    }
    throw new GeneralSecurityException("Unable to serialize algorithm: " + algorithm);
  }

  private static JwtEcdsaParameters.Algorithm toAlgorithm(JwtEcdsaAlgorithm algorithm)
      throws GeneralSecurityException {
    switch (algorithm) {
      case ES256:
        return JwtEcdsaParameters.Algorithm.ES256;
      case ES384:
        return JwtEcdsaParameters.Algorithm.ES384;
      case ES512:
        return JwtEcdsaParameters.Algorithm.ES512;
      default:
        throw new GeneralSecurityException("Unable to parse algorithm: " + algorithm.getNumber());
    }
  }

  private static com.google.crypto.tink.proto.JwtEcdsaKeyFormat serializeToJwtEcdsaKeyFormat(
      JwtEcdsaParameters parameters) throws GeneralSecurityException {
    if (!parameters.getKidStrategy().equals(JwtEcdsaParameters.KidStrategy.IGNORED)
        && !parameters
            .getKidStrategy()
            .equals(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)) {
      throw new GeneralSecurityException(
          "Unable to serialize Parameters object with KidStrategy " + parameters.getKidStrategy());
    }
    return com.google.crypto.tink.proto.JwtEcdsaKeyFormat.newBuilder()
        .setVersion(0)
        .setAlgorithm(toProtoAlgorithm(parameters.getAlgorithm()))
        .build();
  }

  private static ProtoParametersSerialization serializeParameters(JwtEcdsaParameters parameters)
      throws GeneralSecurityException {
    OutputPrefixType outputPrefixType = OutputPrefixType.TINK;
    if (parameters.getKidStrategy().equals(JwtEcdsaParameters.KidStrategy.IGNORED)) {
      outputPrefixType = OutputPrefixType.RAW;
    }
    return ProtoParametersSerialization.create(
        KeyTemplate.newBuilder()
            .setTypeUrl(TYPE_URL)
            .setValue(serializeToJwtEcdsaKeyFormat(parameters).toByteString())
            .setOutputPrefixType(outputPrefixType)
            .build());
  }

  private static JwtEcdsaParameters parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    if (!serialization.getKeyTemplate().getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to JwtEcdsaParameters.parseParameters: "
              + serialization.getKeyTemplate().getTypeUrl());
    }
    com.google.crypto.tink.proto.JwtEcdsaKeyFormat format;
    try {
      format =
          com.google.crypto.tink.proto.JwtEcdsaKeyFormat.parseFrom(
              serialization.getKeyTemplate().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing JwtEcdsaKeyFormat failed: ", e);
    }
    if (format.getVersion() != 0) {
      throw new GeneralSecurityException(
          "Parsing HmacParameters failed: unknown Version " + format.getVersion());
    }
    JwtEcdsaParameters.KidStrategy kidStrategy = null;
    if (serialization.getKeyTemplate().getOutputPrefixType().equals(OutputPrefixType.TINK)) {
      kidStrategy = JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID;
    }
    if (serialization.getKeyTemplate().getOutputPrefixType().equals(OutputPrefixType.RAW)) {
      kidStrategy = JwtEcdsaParameters.KidStrategy.IGNORED;
    }
    if (kidStrategy == null) {
      throw new GeneralSecurityException("Invalid OutputPrefixType for JwtHmacKeyFormat");
    }
    return JwtEcdsaParameters.builder()
        .setAlgorithm(toAlgorithm(format.getAlgorithm()))
        .setKidStrategy(kidStrategy)
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

  private JwtEcdsaProtoSerialization() {}
}
