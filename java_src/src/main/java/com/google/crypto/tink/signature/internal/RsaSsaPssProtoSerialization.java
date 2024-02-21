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

package com.google.crypto.tink.signature.internal;

import static com.google.crypto.tink.internal.Util.toBytesFromPrintableAscii;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.internal.BigIntegerEncoding;
import com.google.crypto.tink.internal.EnumTypeProtoConverter;
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
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.RsaSsaPssPublicKey;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Methods to serialize and parse {@link RsaSsaPssPrivateKey} and {@link RsaSsaPssPublicKey} objects
 * and {@link RsaSsaPssParameters} objects.
 */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class RsaSsaPssProtoSerialization {
  private static final String PRIVATE_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey";
  private static final Bytes PRIVATE_TYPE_URL_BYTES = toBytesFromPrintableAscii(PRIVATE_TYPE_URL);
  private static final String PUBLIC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey";
  private static final Bytes PUBLIC_TYPE_URL_BYTES = toBytesFromPrintableAscii(PUBLIC_TYPE_URL);

  private static final ParametersSerializer<RsaSsaPssParameters, ProtoParametersSerialization>
      PARAMETERS_SERIALIZER =
          ParametersSerializer.create(
              RsaSsaPssProtoSerialization::serializeParameters,
              RsaSsaPssParameters.class,
              ProtoParametersSerialization.class);

  private static final ParametersParser<ProtoParametersSerialization> PARAMETERS_PARSER =
      ParametersParser.create(
          RsaSsaPssProtoSerialization::parseParameters,
          PRIVATE_TYPE_URL_BYTES,
          ProtoParametersSerialization.class);

  private static final KeySerializer<RsaSsaPssPublicKey, ProtoKeySerialization>
      PUBLIC_KEY_SERIALIZER =
          KeySerializer.create(
              RsaSsaPssProtoSerialization::serializePublicKey,
              RsaSsaPssPublicKey.class,
              ProtoKeySerialization.class);

  private static final KeyParser<ProtoKeySerialization> PUBLIC_KEY_PARSER =
      KeyParser.create(
          RsaSsaPssProtoSerialization::parsePublicKey,
          PUBLIC_TYPE_URL_BYTES,
          ProtoKeySerialization.class);

  private static final KeySerializer<RsaSsaPssPrivateKey, ProtoKeySerialization>
      PRIVATE_KEY_SERIALIZER =
          KeySerializer.create(
              RsaSsaPssProtoSerialization::serializePrivateKey,
              RsaSsaPssPrivateKey.class,
              ProtoKeySerialization.class);

  private static final KeyParser<ProtoKeySerialization> PRIVATE_KEY_PARSER =
      KeyParser.create(
          RsaSsaPssProtoSerialization::parsePrivateKey,
          PRIVATE_TYPE_URL_BYTES,
          ProtoKeySerialization.class);

  private static final EnumTypeProtoConverter<OutputPrefixType, RsaSsaPssParameters.Variant>
      VARIANT_CONVERTER =
          EnumTypeProtoConverter.<OutputPrefixType, RsaSsaPssParameters.Variant>builder()
              .add(OutputPrefixType.RAW, RsaSsaPssParameters.Variant.NO_PREFIX)
              .add(OutputPrefixType.TINK, RsaSsaPssParameters.Variant.TINK)
              .add(OutputPrefixType.CRUNCHY, RsaSsaPssParameters.Variant.CRUNCHY)
              .add(OutputPrefixType.LEGACY, RsaSsaPssParameters.Variant.LEGACY)
              .build();

  private static final EnumTypeProtoConverter<HashType, RsaSsaPssParameters.HashType>
      HASH_TYPE_CONVERTER =
          EnumTypeProtoConverter.<HashType, RsaSsaPssParameters.HashType>builder()
              .add(HashType.SHA256, RsaSsaPssParameters.HashType.SHA256)
              .add(HashType.SHA384, RsaSsaPssParameters.HashType.SHA384)
              .add(HashType.SHA512, RsaSsaPssParameters.HashType.SHA512)
              .build();

  private static com.google.crypto.tink.proto.RsaSsaPssParams getProtoParams(
      RsaSsaPssParameters parameters) throws GeneralSecurityException {
    return com.google.crypto.tink.proto.RsaSsaPssParams.newBuilder()
        .setSigHash(HASH_TYPE_CONVERTER.toProtoEnum(parameters.getSigHashType()))
        .setMgf1Hash(HASH_TYPE_CONVERTER.toProtoEnum(parameters.getMgf1HashType()))
        .setSaltLength(parameters.getSaltLengthBytes())
        .build();
  }

  /** Encodes a BigInteger using a big-endian encoding. */
  private static ByteString encodeBigInteger(BigInteger i) {
    // Note that toBigEndianBytes() returns the minimal big-endian encoding using the two's
    // complement representation. This means that the encoding may have a leading zero.
    byte[] encoded = BigIntegerEncoding.toBigEndianBytes(i);
    return ByteString.copyFrom(encoded);
  }

  private static com.google.crypto.tink.proto.RsaSsaPssPublicKey getProtoPublicKey(
      RsaSsaPssPublicKey key) throws GeneralSecurityException {
    return com.google.crypto.tink.proto.RsaSsaPssPublicKey.newBuilder()
        .setParams(getProtoParams(key.getParameters()))
        .setN(encodeBigInteger(key.getModulus()))
        .setE(encodeBigInteger(key.getParameters().getPublicExponent()))
        .setVersion(0)
        .build();
  }

  private static ProtoParametersSerialization serializeParameters(RsaSsaPssParameters parameters)
      throws GeneralSecurityException {
    return ProtoParametersSerialization.create(
        KeyTemplate.newBuilder()
            .setTypeUrl(PRIVATE_TYPE_URL)
            .setValue(
                com.google.crypto.tink.proto.RsaSsaPssKeyFormat.newBuilder()
                    .setParams(getProtoParams(parameters))
                    .setModulusSizeInBits(parameters.getModulusSizeBits())
                    .setPublicExponent(encodeBigInteger(parameters.getPublicExponent()))
                    .build()
                    .toByteString())
            .setOutputPrefixType(VARIANT_CONVERTER.toProtoEnum(parameters.getVariant()))
            .build());
  }

  private static ProtoKeySerialization serializePublicKey(
      RsaSsaPssPublicKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        PUBLIC_TYPE_URL,
        getProtoPublicKey(key).toByteString(),
        KeyMaterialType.ASYMMETRIC_PUBLIC,
        VARIANT_CONVERTER.toProtoEnum(key.getParameters().getVariant()),
        key.getIdRequirementOrNull());
  }

  private static ByteString encodeSecretBigInteger(SecretBigInteger i, SecretKeyAccess access) {
    return encodeBigInteger(i.getBigInteger(access));
  }

  private static ProtoKeySerialization serializePrivateKey(
      RsaSsaPssPrivateKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    SecretKeyAccess a = SecretKeyAccess.requireAccess(access);
    com.google.crypto.tink.proto.RsaSsaPssPrivateKey protoPrivateKey =
        com.google.crypto.tink.proto.RsaSsaPssPrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(getProtoPublicKey(key.getPublicKey()))
            .setD(encodeSecretBigInteger(key.getPrivateExponent(), a))
            .setP(encodeSecretBigInteger(key.getPrimeP(), a))
            .setQ(encodeSecretBigInteger(key.getPrimeQ(), a))
            .setDp(encodeSecretBigInteger(key.getPrimeExponentP(), a))
            .setDq(encodeSecretBigInteger(key.getPrimeExponentQ(), a))
            .setCrt(encodeSecretBigInteger(key.getCrtCoefficient(), a))
            .build();
    return ProtoKeySerialization.create(
        PRIVATE_TYPE_URL,
        protoPrivateKey.toByteString(),
        KeyMaterialType.ASYMMETRIC_PRIVATE,
        VARIANT_CONVERTER.toProtoEnum(key.getParameters().getVariant()),
        key.getIdRequirementOrNull());
  }

  private static BigInteger decodeBigInteger(ByteString data) {
    return BigIntegerEncoding.fromUnsignedBigEndianBytes(data.toByteArray());
  }

  private static RsaSsaPssParameters parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    if (!serialization.getKeyTemplate().getTypeUrl().equals(PRIVATE_TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to RsaSsaPssProtoSerialization.parseParameters: "
              + serialization.getKeyTemplate().getTypeUrl());
    }
    com.google.crypto.tink.proto.RsaSsaPssKeyFormat format;
    try {
      format =
          com.google.crypto.tink.proto.RsaSsaPssKeyFormat.parseFrom(
              serialization.getKeyTemplate().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing RsaSsaPssParameters failed: ", e);
    }
    return RsaSsaPssParameters.builder()
        .setSigHashType(HASH_TYPE_CONVERTER.fromProtoEnum(format.getParams().getSigHash()))
        .setMgf1HashType(HASH_TYPE_CONVERTER.fromProtoEnum(format.getParams().getMgf1Hash()))
        .setPublicExponent(decodeBigInteger(format.getPublicExponent()))
        .setModulusSizeBits(format.getModulusSizeInBits())
        .setSaltLengthBytes(format.getParams().getSaltLength())
        .setVariant(
            VARIANT_CONVERTER.fromProtoEnum(serialization.getKeyTemplate().getOutputPrefixType()))
        .build();
  }

  @SuppressWarnings("UnusedException")
  private static RsaSsaPssPublicKey parsePublicKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(PUBLIC_TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to RsaSsaPssProtoSerialization.parsePublicKey: "
              + serialization.getTypeUrl());
    }
    try {
      com.google.crypto.tink.proto.RsaSsaPssPublicKey protoKey =
          com.google.crypto.tink.proto.RsaSsaPssPublicKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }
      BigInteger modulus = decodeBigInteger(protoKey.getN());
      int modulusSizeInBits = modulus.bitLength();
      RsaSsaPssParameters parameters =
          RsaSsaPssParameters.builder()
              .setSigHashType(HASH_TYPE_CONVERTER.fromProtoEnum(protoKey.getParams().getSigHash()))
              .setMgf1HashType(
                  HASH_TYPE_CONVERTER.fromProtoEnum(protoKey.getParams().getMgf1Hash()))
              .setPublicExponent(decodeBigInteger(protoKey.getE()))
              .setModulusSizeBits(modulusSizeInBits)
              .setSaltLengthBytes(protoKey.getParams().getSaltLength())
              .setVariant(VARIANT_CONVERTER.fromProtoEnum(serialization.getOutputPrefixType()))
              .build();
      return RsaSsaPssPublicKey.builder()
          .setParameters(parameters)
          .setModulus(modulus)
          .setIdRequirement(serialization.getIdRequirementOrNull())
          .build();
    } catch (InvalidProtocolBufferException | IllegalArgumentException e) {
      throw new GeneralSecurityException("Parsing RsaSsaPssPublicKey failed");
    }
  }

  private static SecretBigInteger decodeSecretBigInteger(ByteString data, SecretKeyAccess access) {
    return SecretBigInteger.fromBigInteger(
        BigIntegerEncoding.fromUnsignedBigEndianBytes(data.toByteArray()), access);
  }

  @SuppressWarnings("UnusedException")
  private static RsaSsaPssPrivateKey parsePrivateKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(PRIVATE_TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to RsaSsaPssProtoSerialization.parsePrivateKey: "
              + serialization.getTypeUrl());
    }
    try {
      com.google.crypto.tink.proto.RsaSsaPssPrivateKey protoKey =
          com.google.crypto.tink.proto.RsaSsaPssPrivateKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }
      com.google.crypto.tink.proto.RsaSsaPssPublicKey protoPublicKey = protoKey.getPublicKey();

      BigInteger modulus = decodeBigInteger(protoPublicKey.getN());
      int modulusSizeInBits = modulus.bitLength();
      BigInteger publicExponent = decodeBigInteger(protoPublicKey.getE());
      RsaSsaPssParameters parameters =
          RsaSsaPssParameters.builder()
              .setSigHashType(
                  HASH_TYPE_CONVERTER.fromProtoEnum(protoPublicKey.getParams().getSigHash()))
              .setMgf1HashType(
                  HASH_TYPE_CONVERTER.fromProtoEnum(protoPublicKey.getParams().getMgf1Hash()))
              .setPublicExponent(publicExponent)
              .setModulusSizeBits(modulusSizeInBits)
              .setSaltLengthBytes(protoPublicKey.getParams().getSaltLength())
              .setVariant(VARIANT_CONVERTER.fromProtoEnum(serialization.getOutputPrefixType()))
              .build();
      RsaSsaPssPublicKey publicKey =
          RsaSsaPssPublicKey.builder()
              .setParameters(parameters)
              .setModulus(modulus)
              .setIdRequirement(serialization.getIdRequirementOrNull())
              .build();

      SecretKeyAccess a = SecretKeyAccess.requireAccess(access);
      return RsaSsaPssPrivateKey.builder()
          .setPublicKey(publicKey)
          .setPrimes(
              decodeSecretBigInteger(protoKey.getP(), a),
              decodeSecretBigInteger(protoKey.getQ(), a))
          .setPrivateExponent(decodeSecretBigInteger(protoKey.getD(), a))
          .setPrimeExponents(
              decodeSecretBigInteger(protoKey.getDp(), a),
              decodeSecretBigInteger(protoKey.getDq(), a))
          .setCrtCoefficient(decodeSecretBigInteger(protoKey.getCrt(), a))
          .build();
    } catch (InvalidProtocolBufferException | IllegalArgumentException e) {
      throw new GeneralSecurityException("Parsing RsaSsaPssPrivateKey failed");
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
    registry.registerKeySerializer(PRIVATE_KEY_SERIALIZER);
    registry.registerKeyParser(PRIVATE_KEY_PARSER);
  }

  private RsaSsaPssProtoSerialization() {}
}
