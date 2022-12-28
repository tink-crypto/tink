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

package com.google.crypto.tink.mac;

import static com.google.crypto.tink.internal.Util.toBytesFromPrintableAscii;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.SecretKeyAccess;
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
final class HmacProtoSerialization {
  private static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.HmacKey";
  private static final Bytes TYPE_URL_BYTES = toBytesFromPrintableAscii(TYPE_URL);

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

  private static OutputPrefixType toProtoOutputPrefixType(HmacParameters.Variant variant)
      throws GeneralSecurityException {
    if (HmacParameters.Variant.TINK.equals(variant)) {
      return OutputPrefixType.TINK;
    }
    if (HmacParameters.Variant.CRUNCHY.equals(variant)) {
      return OutputPrefixType.CRUNCHY;
    }
    if (HmacParameters.Variant.NO_PREFIX.equals(variant)) {
      return OutputPrefixType.RAW;
    }
    if (HmacParameters.Variant.LEGACY.equals(variant)) {
      return OutputPrefixType.LEGACY;
    }
    throw new GeneralSecurityException("Unable to serialize variant: " + variant);
  }

  private static HashType toProtoHashType(HmacParameters.HashType hashType)
      throws GeneralSecurityException {
    if (HmacParameters.HashType.SHA1.equals(hashType)) {
      return HashType.SHA1;
    }
    if (HmacParameters.HashType.SHA224.equals(hashType)) {
      return HashType.SHA224;
    }
    if (HmacParameters.HashType.SHA256.equals(hashType)) {
      return HashType.SHA256;
    }
    if (HmacParameters.HashType.SHA384.equals(hashType)) {
      return HashType.SHA384;
    }
    if (HmacParameters.HashType.SHA512.equals(hashType)) {
      return HashType.SHA512;
    }
    throw new GeneralSecurityException("Unable to serialize HashType " + hashType);
  }

  private static HmacParameters.HashType toHashType(HashType hashType)
      throws GeneralSecurityException {
    switch (hashType) {
      case SHA1:
        return HmacParameters.HashType.SHA1;
      case SHA224:
        return HmacParameters.HashType.SHA224;
      case SHA256:
        return HmacParameters.HashType.SHA256;
      case SHA384:
        return HmacParameters.HashType.SHA384;
      case SHA512:
        return HmacParameters.HashType.SHA512;
      default:
        throw new GeneralSecurityException(
            "Unable to parse HashType: " + hashType.getNumber());
    }
  }

  private static HmacParameters.Variant toVariant(OutputPrefixType outputPrefixType)
      throws GeneralSecurityException {
    switch (outputPrefixType) {
      case TINK:
        return HmacParameters.Variant.TINK;
      case CRUNCHY:
        return HmacParameters.Variant.CRUNCHY;
      case LEGACY:
        return HmacParameters.Variant.LEGACY;
      case RAW:
        return HmacParameters.Variant.NO_PREFIX;
      default:
        throw new GeneralSecurityException(
            "Unable to parse OutputPrefixType: " + outputPrefixType.getNumber());
    }
  }

  private static com.google.crypto.tink.proto.HmacParams getProtoParams(HmacParameters parameters)
      throws GeneralSecurityException {
    return com.google.crypto.tink.proto.HmacParams.newBuilder()
        .setTagSize(parameters.getCryptographicTagSizeBytes())
        .setHash(toProtoHashType(parameters.getHashType()))
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
            .setOutputPrefixType(toProtoOutputPrefixType(parameters.getVariant()))
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
        toProtoOutputPrefixType(key.getParameters().getVariant()),
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
        .setHashType(toHashType(format.getParams().getHash()))
        .setVariant(toVariant(serialization.getKeyTemplate().getOutputPrefixType()))
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
              .setHashType(toHashType(protoKey.getParams().getHash()))
              .setVariant(toVariant(serialization.getOutputPrefixType()))
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
