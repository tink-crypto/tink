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
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.internal.EnumTypeProtoConverter;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ParametersParser;
import com.google.crypto.tink.internal.ParametersSerializer;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.EcPointFormat;
import com.google.crypto.tink.proto.EciesAeadHkdfKeyFormat;
import com.google.crypto.tink.proto.EciesAeadHkdfParams;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.Bytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/** Methods to serialize and parse {@link EciesParameters} objects. */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
final class EciesProtoSerialization {
  private static final String PRIVATE_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  private static final Bytes PRIVATE_TYPE_URL_BYTES = toBytesFromPrintableAscii(PRIVATE_TYPE_URL);

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

  private static final EnumTypeProtoConverter<OutputPrefixType, EciesParameters.Variant>
      VARIANT_CONVERTER =
          EnumTypeProtoConverter.<OutputPrefixType, EciesParameters.Variant>builder()
              .add(OutputPrefixType.RAW, EciesParameters.Variant.NO_PREFIX)
              .add(OutputPrefixType.TINK, EciesParameters.Variant.TINK)
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
      demProtoParams =
          com.google.crypto.tink.proto.EciesAeadDemParams.newBuilder()
              .setAeadDem(
                  com.google.crypto.tink.proto.KeyTemplate.parseFrom(
                      TinkProtoParametersFormat.serialize(parameters.getDemParameters()),
                      ExtensionRegistryLite.getEmptyRegistry()))
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
    com.google.crypto.tink.proto.KeyTemplate aeadKeyTemplate =
        protoParams.getDemParams().getAeadDem();
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

  private EciesProtoSerialization() {}
}
