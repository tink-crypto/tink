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
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.internal.BigIntegerEncoding;
import com.google.crypto.tink.internal.KeyParser;
import com.google.crypto.tink.internal.KeySerializer;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ParametersParser;
import com.google.crypto.tink.internal.ParametersSerializer;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.JwtEcdsaAlgorithm;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.Bytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import javax.annotation.Nullable;

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

  private static final String PUBLIC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey";
  private static final Bytes PUBLIC_TYPE_URL_BYTES = toBytesFromPrintableAscii(PUBLIC_TYPE_URL);

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

  private static final KeySerializer<JwtEcdsaPublicKey, ProtoKeySerialization>
      PUBLIC_KEY_SERIALIZER =
          KeySerializer.create(
              JwtEcdsaProtoSerialization::serializePublicKey,
              JwtEcdsaPublicKey.class,
              ProtoKeySerialization.class);

  private static final KeyParser<ProtoKeySerialization> PUBLIC_KEY_PARSER =
      KeyParser.create(
          JwtEcdsaProtoSerialization::parsePublicKey,
          PUBLIC_TYPE_URL_BYTES,
          ProtoKeySerialization.class);

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

  private static int getEncodingLength(JwtEcdsaParameters.Algorithm algorithm)
      throws GeneralSecurityException {
    // We currently encode with one extra 0 byte at the beginning, to make sure
    // that parsing is correct even if passing of a two's complement encoding is used.
    // We want to prevent bugs similar to b/264525021
    if (algorithm.equals(JwtEcdsaParameters.Algorithm.ES256)) {
      return 33;
    }
    if (algorithm.equals(JwtEcdsaParameters.Algorithm.ES384)) {
      return 49;
    }
    if (algorithm.equals(JwtEcdsaParameters.Algorithm.ES512)) {
      return 67;
    }
    throw new GeneralSecurityException("Unknown algorithm: " + algorithm);
  }

  private static OutputPrefixType toProtoOutputPrefixType(JwtEcdsaParameters parameters) {
    if (parameters.getKidStrategy().equals(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)) {
      return OutputPrefixType.TINK;
    }
    return OutputPrefixType.RAW;
  }

  private static com.google.crypto.tink.proto.JwtEcdsaPublicKey serializePublicKey(
      JwtEcdsaPublicKey key) throws GeneralSecurityException {
    int encLength = getEncodingLength(key.getParameters().getAlgorithm());
    ECPoint publicPoint = key.getPublicPoint();
    com.google.crypto.tink.proto.JwtEcdsaPublicKey.Builder builder =
        com.google.crypto.tink.proto.JwtEcdsaPublicKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(toProtoAlgorithm(key.getParameters().getAlgorithm()))
            .setX(
                ByteString.copyFrom(
                    BigIntegerEncoding.toBigEndianBytesOfFixedLength(
                        publicPoint.getAffineX(), encLength)))
            .setY(
                ByteString.copyFrom(
                    BigIntegerEncoding.toBigEndianBytesOfFixedLength(
                        publicPoint.getAffineY(), encLength)));
    if (key.getParameters().getKidStrategy().equals(JwtEcdsaParameters.KidStrategy.CUSTOM)) {
      builder.setCustomKid(
          com.google.crypto.tink.proto.JwtEcdsaPublicKey.CustomKid.newBuilder()
              .setValue(key.getKid().get())
              .build());
    }
    return builder.build();
  }

  private static ProtoKeySerialization serializePublicKey(
      JwtEcdsaPublicKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        PUBLIC_TYPE_URL,
        serializePublicKey(key).toByteString(),
        KeyMaterialType.ASYMMETRIC_PUBLIC,
        toProtoOutputPrefixType(key.getParameters()),
        key.getIdRequirementOrNull());
  }

  @SuppressWarnings("UnusedException")
  private static JwtEcdsaPublicKey parsePublicKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(PUBLIC_TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to EcdsaProtoSerialization.parsePublicKey: "
              + serialization.getTypeUrl());
    }
    try {
      com.google.crypto.tink.proto.JwtEcdsaPublicKey protoKey =
          com.google.crypto.tink.proto.JwtEcdsaPublicKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }
      JwtEcdsaParameters.Builder parametersBuilder = JwtEcdsaParameters.builder();
      JwtEcdsaPublicKey.Builder keyBuilder = JwtEcdsaPublicKey.builder();

      if (serialization.getOutputPrefixType().equals(OutputPrefixType.TINK)) {
        if (protoKey.hasCustomKid()) {
          throw new GeneralSecurityException(
              "Keys serialized with OutputPrefixType TINK should not have a custom kid");
        }
        @Nullable Integer idRequirement = serialization.getIdRequirementOrNull();
        if (idRequirement == null) {
          throw new GeneralSecurityException(
              "Keys serialized with OutputPrefixType TINK need an ID Requirement");
        }
        parametersBuilder.setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID);
        keyBuilder.setIdRequirement(idRequirement);
      } else if (serialization.getOutputPrefixType().equals(OutputPrefixType.RAW)) {
        if (protoKey.hasCustomKid()) {
          parametersBuilder.setKidStrategy(JwtEcdsaParameters.KidStrategy.CUSTOM);
          keyBuilder.setCustomKid(protoKey.getCustomKid().getValue());
        } else {
          parametersBuilder.setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED);
        }
      }
      parametersBuilder.setAlgorithm(toAlgorithm(protoKey.getAlgorithm()));
      keyBuilder.setPublicPoint(
          new ECPoint(
              BigIntegerEncoding.fromUnsignedBigEndianBytes(protoKey.getX().toByteArray()),
              BigIntegerEncoding.fromUnsignedBigEndianBytes(protoKey.getY().toByteArray())));
      return keyBuilder.setParameters(parametersBuilder.build()).build();
    } catch (InvalidProtocolBufferException | IllegalArgumentException e) {
      throw new GeneralSecurityException("Parsing EcdsaPublicKey failed");
    }
  }

  public static void register() throws GeneralSecurityException {
    register(MutableSerializationRegistry.globalInstance());
  }

  public static void register(MutableSerializationRegistry registry)
      throws GeneralSecurityException {
    registry.registerParametersSerializer(PARAMETERS_SERIALIZER);
    registry.registerParametersParser(PARAMETERS_PARSER);
    registry.registerKeySerializer(PUBLIC_KEY_SERIALIZER);
    registry.registerKeyParser(PUBLIC_KEY_PARSER);
  }

  private JwtEcdsaProtoSerialization() {}
}
