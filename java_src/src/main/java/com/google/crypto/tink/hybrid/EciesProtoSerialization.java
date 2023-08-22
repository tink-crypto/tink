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

package com.google.crypto.tink.hybrid;

import static com.google.crypto.tink.internal.Util.toBytesFromPrintableAscii;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.internal.BigIntegerEncoding;
import com.google.crypto.tink.internal.EnumTypeProtoConverter;
import com.google.crypto.tink.internal.KeyParser;
import com.google.crypto.tink.internal.KeySerializer;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ParametersParser;
import com.google.crypto.tink.internal.ParametersSerializer;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.EcPointFormat;
import com.google.crypto.tink.proto.EciesAeadHkdfKeyFormat;
import com.google.crypto.tink.proto.EciesAeadHkdfParams;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import javax.annotation.Nullable;

/** Methods to serialize and parse {@link EciesParameters} objects. */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
final class EciesProtoSerialization {
  private static final String PRIVATE_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  private static final Bytes PRIVATE_TYPE_URL_BYTES = toBytesFromPrintableAscii(PRIVATE_TYPE_URL);

  private static final String PUBLIC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";
  private static final Bytes PUBLIC_TYPE_URL_BYTES = toBytesFromPrintableAscii(PUBLIC_TYPE_URL);

  private static final ParametersSerializer<EciesParameters, ProtoParametersSerialization>
      PARAMETERS_SERIALIZER =
          ParametersSerializer.create(
              EciesProtoSerialization::serializeParameters,
              EciesParameters.class,
              ProtoParametersSerialization.class);

  private static final ParametersParser<ProtoParametersSerialization> PARAMETERS_PARSER =
      ParametersParser.create(
          EciesProtoSerialization::parseParameters,
          PRIVATE_TYPE_URL_BYTES,
          ProtoParametersSerialization.class);

  private static final KeySerializer<EciesPublicKey, ProtoKeySerialization> PUBLIC_KEY_SERIALIZER =
      KeySerializer.create(
          EciesProtoSerialization::serializePublicKey,
          EciesPublicKey.class,
          ProtoKeySerialization.class);

  private static final KeyParser<ProtoKeySerialization> PUBLIC_KEY_PARSER =
      KeyParser.create(
          EciesProtoSerialization::parsePublicKey,
          PUBLIC_TYPE_URL_BYTES,
          ProtoKeySerialization.class);

  private static final KeySerializer<EciesPrivateKey, ProtoKeySerialization>
      PRIVATE_KEY_SERIALIZER =
          KeySerializer.create(
              EciesProtoSerialization::serializePrivateKey,
              EciesPrivateKey.class,
              ProtoKeySerialization.class);

  private static final KeyParser<ProtoKeySerialization> PRIVATE_KEY_PARSER =
      KeyParser.create(
          EciesProtoSerialization::parsePrivateKey,
          PRIVATE_TYPE_URL_BYTES,
          ProtoKeySerialization.class);

  private static final EnumTypeProtoConverter<OutputPrefixType, EciesParameters.Variant>
      VARIANT_CONVERTER =
          EnumTypeProtoConverter.<OutputPrefixType, EciesParameters.Variant>builder()
              .add(OutputPrefixType.RAW, EciesParameters.Variant.NO_PREFIX)
              .add(OutputPrefixType.TINK, EciesParameters.Variant.TINK)
              .add(OutputPrefixType.LEGACY, EciesParameters.Variant.CRUNCHY)
              // WARNING: The following mapping MUST be added last to ensure that
              // {@code HpkeParameters.Variant.CRUNCHY} keys are correctly serialized to
              // {@code OutputPrefixType.CRUNCHY} proto keys. Specifically, the most recent entry
              // overrides that toProtoEnum mapping.
              .add(OutputPrefixType.CRUNCHY, EciesParameters.Variant.CRUNCHY)
              .build();

  private static final EnumTypeProtoConverter<HashType, EciesParameters.HashType>
      HASH_TYPE_CONVERTER =
          EnumTypeProtoConverter.<HashType, EciesParameters.HashType>builder()
              .add(HashType.SHA1, EciesParameters.HashType.SHA1)
              .add(HashType.SHA224, EciesParameters.HashType.SHA224)
              .add(HashType.SHA256, EciesParameters.HashType.SHA256)
              .add(HashType.SHA384, EciesParameters.HashType.SHA384)
              .add(HashType.SHA512, EciesParameters.HashType.SHA512)
              .build();

  private static final EnumTypeProtoConverter<EllipticCurveType, EciesParameters.CurveType>
      CURVE_TYPE_CONVERTER =
          EnumTypeProtoConverter.<EllipticCurveType, EciesParameters.CurveType>builder()
              .add(EllipticCurveType.NIST_P256, EciesParameters.CurveType.NIST_P256)
              .add(EllipticCurveType.NIST_P384, EciesParameters.CurveType.NIST_P384)
              .add(EllipticCurveType.NIST_P521, EciesParameters.CurveType.NIST_P521)
              .add(EllipticCurveType.CURVE25519, EciesParameters.CurveType.X25519)
              .build();

  private static final EnumTypeProtoConverter<EcPointFormat, EciesParameters.PointFormat>
      POINT_FORMAT_CONVERTER =
          EnumTypeProtoConverter.<EcPointFormat, EciesParameters.PointFormat>builder()
              .add(EcPointFormat.UNCOMPRESSED, EciesParameters.PointFormat.UNCOMPRESSED)
              .add(EcPointFormat.COMPRESSED, EciesParameters.PointFormat.COMPRESSED)
              .add(
                  EcPointFormat.DO_NOT_USE_CRUNCHY_UNCOMPRESSED,
                  EciesParameters.PointFormat.LEGACY_UNCOMPRESSED)
              .build();

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
    registry.registerKeySerializer(PUBLIC_KEY_SERIALIZER);
    registry.registerKeyParser(PUBLIC_KEY_PARSER);
    registry.registerKeySerializer(PRIVATE_KEY_SERIALIZER);
    registry.registerKeyParser(PRIVATE_KEY_PARSER);
  }

  private static com.google.crypto.tink.proto.EciesAeadHkdfParams toProtoParameters(
      EciesParameters parameters) throws GeneralSecurityException {
    com.google.crypto.tink.proto.EciesHkdfKemParams.Builder kemProtoParamsBuilder =
        com.google.crypto.tink.proto.EciesHkdfKemParams.newBuilder()
            .setCurveType(CURVE_TYPE_CONVERTER.toProtoEnum(parameters.getCurveType()))
            .setHkdfHashType(HASH_TYPE_CONVERTER.toProtoEnum(parameters.getHashType()));
    if (parameters.getSalt() != null && parameters.getSalt().size() > 0) {
      kemProtoParamsBuilder.setHkdfSalt(ByteString.copyFrom(parameters.getSalt().toByteArray()));
    }
    com.google.crypto.tink.proto.EciesHkdfKemParams kemProtoParams = kemProtoParamsBuilder.build();

    com.google.crypto.tink.proto.EciesAeadDemParams demProtoParams;
    try {
      KeyTemplate demKeyTemplate =
          KeyTemplate.parseFrom(
              TinkProtoParametersFormat.serialize(parameters.getDemParameters()),
              ExtensionRegistryLite.getEmptyRegistry());
      demProtoParams =
          // Always set OutputPrefixType to TINK when serializing. This is to maintain consistency
          // among the languages.
          com.google.crypto.tink.proto.EciesAeadDemParams.newBuilder()
              .setAeadDem(
                  com.google.crypto.tink.proto.KeyTemplate.newBuilder()
                      .setTypeUrl(demKeyTemplate.getTypeUrl())
                      .setOutputPrefixType(OutputPrefixType.TINK)
                      .setValue(demKeyTemplate.getValue())
                      .build())
              .build();
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing EciesParameters failed: ", e);
    }

    @Nullable EciesParameters.PointFormat pointFormat = parameters.getNistCurvePointFormat();
    // Null only for X25519 in which case we want compressed.
    if (pointFormat == null) {
      pointFormat = EciesParameters.PointFormat.COMPRESSED;
    }
    return com.google.crypto.tink.proto.EciesAeadHkdfParams.newBuilder()
        .setKemParams(kemProtoParams)
        .setDemParams(demProtoParams)
        .setEcPointFormat(POINT_FORMAT_CONVERTER.toProtoEnum(pointFormat))
        .build();
  }

  private static EciesParameters fromProtoParameters(
      OutputPrefixType outputPrefixType, EciesAeadHkdfParams protoParams)
      throws GeneralSecurityException {
    /* Set OutputPrefixType to RAW when parsing the DEM parameters */
    com.google.crypto.tink.proto.KeyTemplate aeadKeyTemplate =
        com.google.crypto.tink.proto.KeyTemplate.newBuilder()
            .setTypeUrl(protoParams.getDemParams().getAeadDem().getTypeUrl())
            .setOutputPrefixType(OutputPrefixType.RAW)
            .setValue(protoParams.getDemParams().getAeadDem().getValue())
            .build();

    EciesParameters.Builder builder =
        EciesParameters.builder()
            .setVariant(VARIANT_CONVERTER.fromProtoEnum(outputPrefixType))
            .setCurveType(
                CURVE_TYPE_CONVERTER.fromProtoEnum(protoParams.getKemParams().getCurveType()))
            .setHashType(
                HASH_TYPE_CONVERTER.fromProtoEnum(protoParams.getKemParams().getHkdfHashType()))
            .setDemParameters(TinkProtoParametersFormat.parse(aeadKeyTemplate.toByteArray()))
            .setSalt(Bytes.copyFrom(protoParams.getKemParams().getHkdfSalt().toByteArray()));
    if (!protoParams.getKemParams().getCurveType().equals(EllipticCurveType.CURVE25519)) {
      builder.setNistCurvePointFormat(
          POINT_FORMAT_CONVERTER.fromProtoEnum(protoParams.getEcPointFormat()));
    } else {
      if (!protoParams.getEcPointFormat().equals(EcPointFormat.COMPRESSED)) {
        throw new GeneralSecurityException("For CURVE25519 EcPointFormat must be compressed");
      }
    }
    return builder.build();
  }

  private static int getEncodingLength(EciesParameters.CurveType curveType)
      throws GeneralSecurityException {
    // We currently encode with one extra 0 byte at the beginning, to make sure
    // that parsing is correct even if passing of a two's complement encoding is used.
    // See also b/264525021.
    if (EciesParameters.CurveType.NIST_P256.equals(curveType)) {
      return 33;
    }
    if (EciesParameters.CurveType.NIST_P384.equals(curveType)) {
      return 49;
    }
    if (EciesParameters.CurveType.NIST_P521.equals(curveType)) {
      return 67;
    }
    throw new GeneralSecurityException("Unable to serialize CurveType " + curveType);
  }

  private static com.google.crypto.tink.proto.EciesAeadHkdfPublicKey toProtoPublicKey(
      EciesPublicKey key) throws GeneralSecurityException {
    if (key.getParameters().getCurveType().equals(EciesParameters.CurveType.X25519)) {
      return com.google.crypto.tink.proto.EciesAeadHkdfPublicKey.newBuilder()
          .setVersion(0)
          .setParams(toProtoParameters(key.getParameters()))
          .setX(ByteString.copyFrom(key.getX25519CurvePointBytes().toByteArray()))
          .setY(ByteString.EMPTY)
          .build();
    }

    int encLength = getEncodingLength(key.getParameters().getCurveType());
    ECPoint publicPoint = key.getNistCurvePoint();
    if (publicPoint == null) {
      throw new GeneralSecurityException("NistCurvePoint was null for NIST curve");
    }
    return com.google.crypto.tink.proto.EciesAeadHkdfPublicKey.newBuilder()
        .setVersion(0)
        .setParams(toProtoParameters(key.getParameters()))
        .setX(
            ByteString.copyFrom(
                BigIntegerEncoding.toBigEndianBytesOfFixedLength(
                    publicPoint.getAffineX(), encLength)))
        .setY(
            ByteString.copyFrom(
                BigIntegerEncoding.toBigEndianBytesOfFixedLength(
                    publicPoint.getAffineY(), encLength)))
        .build();
  }

  private static com.google.crypto.tink.proto.EciesAeadHkdfPrivateKey toProtoPrivateKey(
      EciesPrivateKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    com.google.crypto.tink.proto.EciesAeadHkdfPrivateKey.Builder builder =
        com.google.crypto.tink.proto.EciesAeadHkdfPrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(toProtoPublicKey(key.getPublicKey()));
    if (key.getParameters().getCurveType().equals(EciesParameters.CurveType.X25519)) {
      builder.setKeyValue(
          ByteString.copyFrom(
              key.getX25519PrivateKeyBytes().toByteArray(SecretKeyAccess.requireAccess(access))));
    } else {
      int encLength = getEncodingLength(key.getParameters().getCurveType());
      builder.setKeyValue(
          ByteString.copyFrom(
              BigIntegerEncoding.toBigEndianBytesOfFixedLength(
                  key.getNistPrivateKeyValue().getBigInteger(SecretKeyAccess.requireAccess(access)),
                  encLength)));
    }
    return builder.build();
  }

  private static ProtoParametersSerialization serializeParameters(EciesParameters parameters)
      throws GeneralSecurityException {
    return ProtoParametersSerialization.create(
        com.google.crypto.tink.proto.KeyTemplate.newBuilder()
            .setTypeUrl(PRIVATE_TYPE_URL)
            .setValue(
                EciesAeadHkdfKeyFormat.newBuilder()
                    .setParams(toProtoParameters(parameters))
                    .build()
                    .toByteString())
            .setOutputPrefixType(VARIANT_CONVERTER.toProtoEnum(parameters.getVariant()))
            .build());
  }

  private static ProtoKeySerialization serializePublicKey(
      EciesPublicKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        PUBLIC_TYPE_URL,
        toProtoPublicKey(key).toByteString(),
        KeyMaterialType.ASYMMETRIC_PUBLIC,
        VARIANT_CONVERTER.toProtoEnum(key.getParameters().getVariant()),
        key.getIdRequirementOrNull());
  }

  private static ProtoKeySerialization serializePrivateKey(
      EciesPrivateKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        PRIVATE_TYPE_URL,
        toProtoPrivateKey(key, access).toByteString(),
        KeyMaterialType.ASYMMETRIC_PRIVATE,
        VARIANT_CONVERTER.toProtoEnum(key.getParameters().getVariant()),
        key.getIdRequirementOrNull());
  }

  private static EciesParameters parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    if (!serialization.getKeyTemplate().getTypeUrl().equals(PRIVATE_TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to EciesProtoSerialization.parseParameters: "
              + serialization.getKeyTemplate().getTypeUrl());
    }
    EciesAeadHkdfKeyFormat format;
    try {
      format =
          EciesAeadHkdfKeyFormat.parseFrom(
              serialization.getKeyTemplate().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing EciesParameters failed: ", e);
    }
    return fromProtoParameters(
        serialization.getKeyTemplate().getOutputPrefixType(), format.getParams());
  }

  @SuppressWarnings("UnusedException")
  private static EciesPublicKey parsePublicKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(PUBLIC_TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to EciesProtoSerialization.parsePublicKey: "
              + serialization.getTypeUrl());
    }
    try {
      com.google.crypto.tink.proto.EciesAeadHkdfPublicKey protoKey =
          com.google.crypto.tink.proto.EciesAeadHkdfPublicKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }
      EciesParameters parameters =
          fromProtoParameters(serialization.getOutputPrefixType(), protoKey.getParams());
      if (parameters.getCurveType().equals(EciesParameters.CurveType.X25519)) {
        if (!protoKey.getY().isEmpty()) {
          throw new GeneralSecurityException("Y must be empty for X25519 points");
        }
        return EciesPublicKey.createForCurveX25519(
            parameters,
            Bytes.copyFrom(protoKey.getX().toByteArray()),
            serialization.getIdRequirementOrNull());
      }
      ECPoint point =
          new ECPoint(
              BigIntegerEncoding.fromUnsignedBigEndianBytes(protoKey.getX().toByteArray()),
              BigIntegerEncoding.fromUnsignedBigEndianBytes(protoKey.getY().toByteArray()));

      return EciesPublicKey.createForNistCurve(
          parameters, point, serialization.getIdRequirementOrNull());
    } catch (InvalidProtocolBufferException | IllegalArgumentException e) {
      throw new GeneralSecurityException("Parsing EcdsaPublicKey failed");
    }
  }

  @SuppressWarnings("UnusedException")
  private static EciesPrivateKey parsePrivateKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(PRIVATE_TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to EciesProtoSerialization.parsePrivateKey: "
              + serialization.getTypeUrl());
    }
    try {
      com.google.crypto.tink.proto.EciesAeadHkdfPrivateKey protoKey =
          com.google.crypto.tink.proto.EciesAeadHkdfPrivateKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }
      com.google.crypto.tink.proto.EciesAeadHkdfPublicKey protoPublicKey = protoKey.getPublicKey();
      EciesParameters parameters =
          fromProtoParameters(serialization.getOutputPrefixType(), protoPublicKey.getParams());
      if (parameters.getCurveType().equals(EciesParameters.CurveType.X25519)) {
        EciesPublicKey publicKey =
            EciesPublicKey.createForCurveX25519(
                parameters,
                Bytes.copyFrom(protoPublicKey.getX().toByteArray()),
                serialization.getIdRequirementOrNull());
        return EciesPrivateKey.createForCurveX25519(
            publicKey,
            SecretBytes.copyFrom(
                protoKey.getKeyValue().toByteArray(), SecretKeyAccess.requireAccess(access)));
      }
      ECPoint point =
          new ECPoint(
              BigIntegerEncoding.fromUnsignedBigEndianBytes(protoPublicKey.getX().toByteArray()),
              BigIntegerEncoding.fromUnsignedBigEndianBytes(protoPublicKey.getY().toByteArray()));

      EciesPublicKey publicKey =
          EciesPublicKey.createForNistCurve(
              parameters, point, serialization.getIdRequirementOrNull());
      return EciesPrivateKey.createForNistCurve(
          publicKey,
          SecretBigInteger.fromBigInteger(
              BigIntegerEncoding.fromUnsignedBigEndianBytes(protoKey.getKeyValue().toByteArray()),
              SecretKeyAccess.requireAccess(access)));
    } catch (InvalidProtocolBufferException | IllegalArgumentException e) {
      throw new GeneralSecurityException("Parsing EcdsaPrivateKey failed");
    }
  }

  private EciesProtoSerialization() {}
}
