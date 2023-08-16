// Copyright 2022 Google LLC
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

package com.google.crypto.tink.mac.internal;

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
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.HmacParameters;
import com.google.crypto.tink.proto.HashType;
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

/** Methods to serialize and parse {@link HmacKey} objects and {@link HmacParameters} objects. */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class HmacProtoSerialization {
  private static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.HmacKey";
  private static final Bytes TYPE_URL_BYTES = toBytesFromPrintableAscii(TYPE_URL);
  private static final EnumTypeProtoConverter<OutputPrefixType, HmacParameters.Variant>
      OUTPUT_PREFIX_TYPE_CONVERTER =
          EnumTypeProtoConverter.<OutputPrefixType, HmacParameters.Variant>builder()
              .add(OutputPrefixType.RAW, HmacParameters.Variant.NO_PREFIX)
              .add(OutputPrefixType.TINK, HmacParameters.Variant.TINK)
              .add(OutputPrefixType.LEGACY, HmacParameters.Variant.LEGACY)
              .add(OutputPrefixType.CRUNCHY, HmacParameters.Variant.CRUNCHY)
              .build();
  private static final EnumTypeProtoConverter<HashType, HmacParameters.HashType>
      HASH_TYPE_CONVERTER =
          EnumTypeProtoConverter.<HashType, HmacParameters.HashType>builder()
              .add(HashType.SHA1, HmacParameters.HashType.SHA1)
              .add(HashType.SHA224, HmacParameters.HashType.SHA224)
              .add(HashType.SHA256, HmacParameters.HashType.SHA256)
              .add(HashType.SHA384, HmacParameters.HashType.SHA384)
              .add(HashType.SHA512, HmacParameters.HashType.SHA512)
              .build();

  private static final ParametersSerializer<HmacParameters, ProtoParametersSerialization>
      PARAMETERS_SERIALIZER =
          ParametersSerializer.create(
              HmacProtoSerialization::serializeParameters,
              HmacParameters.class,
              ProtoParametersSerialization.class);

  private static final ParametersParser<ProtoParametersSerialization> PARAMETERS_PARSER =
      ParametersParser.create(
          HmacProtoSerialization::parseParameters,
          TYPE_URL_BYTES,
          ProtoParametersSerialization.class);

  private static final KeySerializer<HmacKey, ProtoKeySerialization> KEY_SERIALIZER =
      KeySerializer.create(
          HmacProtoSerialization::serializeKey, HmacKey.class, ProtoKeySerialization.class);

  private static final KeyParser<ProtoKeySerialization> KEY_PARSER =
      KeyParser.create(
          HmacProtoSerialization::parseKey, TYPE_URL_BYTES, ProtoKeySerialization.class);

  private static com.google.crypto.tink.proto.HmacParams getProtoParams(HmacParameters parameters)
      throws GeneralSecurityException {
    return com.google.crypto.tink.proto.HmacParams.newBuilder()
        .setTagSize(parameters.getCryptographicTagSizeBytes())
        .setHash(HASH_TYPE_CONVERTER.toProtoEnum(parameters.getHashType()))
        .build();
  }

  private static ProtoParametersSerialization serializeParameters(HmacParameters parameters)
      throws GeneralSecurityException {
    return ProtoParametersSerialization.create(
        KeyTemplate.newBuilder()
            .setTypeUrl(TYPE_URL)
            .setValue(
                com.google.crypto.tink.proto.HmacKeyFormat.newBuilder()
                    .setParams(getProtoParams(parameters))
                    .setKeySize(parameters.getKeySizeBytes())
                    .build()
                    .toByteString())
            .setOutputPrefixType(OUTPUT_PREFIX_TYPE_CONVERTER.toProtoEnum(parameters.getVariant()))
            .build());
  }

  private static ProtoKeySerialization serializeKey(HmacKey key, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        TYPE_URL,
        com.google.crypto.tink.proto.HmacKey.newBuilder()
            .setParams(getProtoParams(key.getParameters()))
            .setKeyValue(
                ByteString.copyFrom(
                    key.getKeyBytes().toByteArray(SecretKeyAccess.requireAccess(access))))
            .build()
            .toByteString(),
        KeyMaterialType.SYMMETRIC,
        OUTPUT_PREFIX_TYPE_CONVERTER.toProtoEnum(key.getParameters().getVariant()),
        key.getIdRequirementOrNull());
  }

  private static HmacParameters parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    if (!serialization.getKeyTemplate().getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to HmacProtoSerialization.parseParameters: "
              + serialization.getKeyTemplate().getTypeUrl());
    }
    com.google.crypto.tink.proto.HmacKeyFormat format;
    try {
      format =
          com.google.crypto.tink.proto.HmacKeyFormat.parseFrom(
              serialization.getKeyTemplate().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing HmacParameters failed: ", e);
    }
    if (format.getVersion() != 0) {
      throw new GeneralSecurityException(
          "Parsing HmacParameters failed: unknown Version " + format.getVersion());
    }
    return HmacParameters.builder()
        .setKeySizeBytes(format.getKeySize())
        .setTagSizeBytes(format.getParams().getTagSize())
        .setHashType(HASH_TYPE_CONVERTER.fromProtoEnum(format.getParams().getHash()))
        .setVariant(
            OUTPUT_PREFIX_TYPE_CONVERTER.fromProtoEnum(
                serialization.getKeyTemplate().getOutputPrefixType()))
        .build();
  }

  @SuppressWarnings("UnusedException")
  private static HmacKey parseKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to HmacProtoSerialization.parseKey");
    }
    try {
      com.google.crypto.tink.proto.HmacKey protoKey =
          com.google.crypto.tink.proto.HmacKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }
      HmacParameters parameters =
          HmacParameters.builder()
              .setKeySizeBytes(protoKey.getKeyValue().size())
              .setTagSizeBytes(protoKey.getParams().getTagSize())
              .setHashType(HASH_TYPE_CONVERTER.fromProtoEnum(protoKey.getParams().getHash()))
              .setVariant(
                  OUTPUT_PREFIX_TYPE_CONVERTER.fromProtoEnum(serialization.getOutputPrefixType()))
              .build();
      return HmacKey.builder()
          .setParameters(parameters)
          .setKeyBytes(
              SecretBytes.copyFrom(
                  protoKey.getKeyValue().toByteArray(), SecretKeyAccess.requireAccess(access)))
          .setIdRequirement(serialization.getIdRequirementOrNull())
          .build();
    } catch (InvalidProtocolBufferException | IllegalArgumentException e) {
      throw new GeneralSecurityException("Parsing HmacKey failed");
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

  private HmacProtoSerialization() {}
}
