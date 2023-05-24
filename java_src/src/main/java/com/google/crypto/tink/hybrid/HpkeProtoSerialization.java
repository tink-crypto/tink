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
import com.google.crypto.tink.internal.EnumTypeProtoConverter;
import com.google.crypto.tink.internal.KeyParser;
import com.google.crypto.tink.internal.KeySerializer;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ParametersParser;
import com.google.crypto.tink.internal.ParametersSerializer;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.HpkeAead;
import com.google.crypto.tink.proto.HpkeKdf;
import com.google.crypto.tink.proto.HpkeKem;
import com.google.crypto.tink.proto.HpkeKeyFormat;
import com.google.crypto.tink.proto.HpkeParams;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.Bytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Methods to serialize and parse {@link HpkePrivateKey}, {@link HpkePublicKey}, and {@link
 * HpkeParameters} objects.
 */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
final class HpkeProtoSerialization {
  private static final int VERSION = 0;
  private static final String PRIVATE_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.HpkePrivateKey";
  private static final Bytes PRIVATE_TYPE_URL_BYTES = toBytesFromPrintableAscii(PRIVATE_TYPE_URL);
  private static final String PUBLIC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.HpkePublicKey";
  private static final Bytes PUBLIC_TYPE_URL_BYTES = toBytesFromPrintableAscii(PUBLIC_TYPE_URL);

  private static final ParametersSerializer<HpkeParameters, ProtoParametersSerialization>
      PARAMETERS_SERIALIZER =
          ParametersSerializer.create(
              HpkeProtoSerialization::serializeParameters,
              HpkeParameters.class,
              ProtoParametersSerialization.class);

  private static final ParametersParser<ProtoParametersSerialization> PARAMETERS_PARSER =
      ParametersParser.create(
          HpkeProtoSerialization::parseParameters,
          PRIVATE_TYPE_URL_BYTES,
          ProtoParametersSerialization.class);

  private static final KeySerializer<HpkePublicKey, ProtoKeySerialization> PUBLIC_KEY_SERIALIZER =
      KeySerializer.create(
          HpkeProtoSerialization::serializePublicKey,
          HpkePublicKey.class,
          ProtoKeySerialization.class);

  private static final KeyParser<ProtoKeySerialization> PUBLIC_KEY_PARSER =
      KeyParser.create(
          HpkeProtoSerialization::parsePublicKey,
          PUBLIC_TYPE_URL_BYTES,
          ProtoKeySerialization.class);

  private static final EnumTypeProtoConverter<OutputPrefixType, HpkeParameters.Variant>
      VARIANT_TYPE_CONVERTER =
          EnumTypeProtoConverter.<OutputPrefixType, HpkeParameters.Variant>builder()
              .add(OutputPrefixType.RAW, HpkeParameters.Variant.NO_PREFIX)
              .add(OutputPrefixType.TINK, HpkeParameters.Variant.TINK)
              .add(OutputPrefixType.CRUNCHY, HpkeParameters.Variant.CRUNCHY)
              .build();

  private static final EnumTypeProtoConverter<HpkeKem, HpkeParameters.KemId> KEM_TYPE_CONVERTER =
      EnumTypeProtoConverter.<HpkeKem, HpkeParameters.KemId>builder()
          .add(HpkeKem.DHKEM_P256_HKDF_SHA256, HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
          .add(HpkeKem.DHKEM_P384_HKDF_SHA384, HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384)
          .add(HpkeKem.DHKEM_P521_HKDF_SHA512, HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512)
          .add(HpkeKem.DHKEM_X25519_HKDF_SHA256, HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
          .build();

  private static final EnumTypeProtoConverter<HpkeKdf, HpkeParameters.KdfId> KDF_TYPE_CONVERTER =
      EnumTypeProtoConverter.<HpkeKdf, HpkeParameters.KdfId>builder()
          .add(HpkeKdf.HKDF_SHA256, HpkeParameters.KdfId.HKDF_SHA256)
          .add(HpkeKdf.HKDF_SHA384, HpkeParameters.KdfId.HKDF_SHA384)
          .add(HpkeKdf.HKDF_SHA512, HpkeParameters.KdfId.HKDF_SHA512)
          .build();

  private static final EnumTypeProtoConverter<HpkeAead, HpkeParameters.AeadId> AEAD_TYPE_CONVERTER =
      EnumTypeProtoConverter.<HpkeAead, HpkeParameters.AeadId>builder()
          .add(HpkeAead.AES_128_GCM, HpkeParameters.AeadId.AES_128_GCM)
          .add(HpkeAead.AES_256_GCM, HpkeParameters.AeadId.AES_256_GCM)
          .add(HpkeAead.CHACHA20_POLY1305, HpkeParameters.AeadId.CHACHA20_POLY1305)
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
  }

  private static com.google.crypto.tink.proto.HpkeParams toProtoParameters(HpkeParameters params)
      throws GeneralSecurityException {
    return com.google.crypto.tink.proto.HpkeParams.newBuilder()
        .setKem(KEM_TYPE_CONVERTER.toProtoEnum(params.getKemId()))
        .setKdf(KDF_TYPE_CONVERTER.toProtoEnum(params.getKdfId()))
        .setAead(AEAD_TYPE_CONVERTER.toProtoEnum(params.getAeadId()))
        .build();
  }

  private static com.google.crypto.tink.proto.HpkePublicKey toProtoPublicKey(HpkePublicKey key)
      throws GeneralSecurityException {
    return com.google.crypto.tink.proto.HpkePublicKey.newBuilder()
        .setVersion(VERSION)
        .setParams(toProtoParameters(key.getParameters()))
        .setPublicKey(ByteString.copyFrom(key.getPublicKeyBytes().toByteArray()))
        .build();
  }

  private static HpkeParameters fromProtoParameters(
      OutputPrefixType outputPrefixType, HpkeParams protoParams) throws GeneralSecurityException {
    return HpkeParameters.builder()
        .setVariant(VARIANT_TYPE_CONVERTER.fromProtoEnum(outputPrefixType))
        .setKemId(KEM_TYPE_CONVERTER.fromProtoEnum(protoParams.getKem()))
        .setKdfId(KDF_TYPE_CONVERTER.fromProtoEnum(protoParams.getKdf()))
        .setAeadId(AEAD_TYPE_CONVERTER.fromProtoEnum(protoParams.getAead()))
        .build();
  }

  private static ProtoParametersSerialization serializeParameters(HpkeParameters parameters)
      throws GeneralSecurityException {
    return ProtoParametersSerialization.create(
        KeyTemplate.newBuilder()
            .setTypeUrl(PRIVATE_TYPE_URL)
            .setValue(
                HpkeKeyFormat.newBuilder()
                    .setParams(toProtoParameters(parameters))
                    .build()
                    .toByteString())
            .setOutputPrefixType(VARIANT_TYPE_CONVERTER.toProtoEnum(parameters.getVariant()))
            .build());
  }

  /**
   * Returns the proto serialization of a {@link HpkePublicKey}.
   *
   * @param access may be null for public key material
   * @throws GeneralSecurityException if the key cannot be serialized (e.g. unknown variant)
   */
  private static ProtoKeySerialization serializePublicKey(
      HpkePublicKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        PUBLIC_TYPE_URL,
        toProtoPublicKey(key).toByteString(),
        KeyMaterialType.ASYMMETRIC_PUBLIC,
        VARIANT_TYPE_CONVERTER.toProtoEnum(key.getParameters().getVariant()),
        key.getIdRequirementOrNull());
  }

  private static HpkeParameters parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    if (!serialization.getKeyTemplate().getTypeUrl().equals(PRIVATE_TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to HpkeProtoSerialization.parseParameters: "
              + serialization.getKeyTemplate().getTypeUrl());
    }
    HpkeKeyFormat format;
    try {
      format =
          HpkeKeyFormat.parseFrom(
              serialization.getKeyTemplate().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing HpkeParameters failed: ", e);
    }
    return fromProtoParameters(
        serialization.getKeyTemplate().getOutputPrefixType(), format.getParams());
  }

  @SuppressWarnings("UnusedException")
  private static HpkePublicKey parsePublicKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(PUBLIC_TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to HpkeProtoSerialization.parsePublicKey: "
              + serialization.getTypeUrl());
    }
    try {
      com.google.crypto.tink.proto.HpkePublicKey protoKey =
          com.google.crypto.tink.proto.HpkePublicKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != VERSION) {
        throw new GeneralSecurityException("Only version " + VERSION + " keys are accepted");
      }

      HpkeParameters params =
          fromProtoParameters(serialization.getOutputPrefixType(), protoKey.getParams());
      return HpkePublicKey.create(
          params,
          Bytes.copyFrom(protoKey.getPublicKey().toByteArray()),
          serialization.getIdRequirementOrNull());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing HpkePublicKey failed");
    }
  }

  private HpkeProtoSerialization() {}
}
