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

package com.google.crypto.tink.aead;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.testing.Asserts.assertEqualWhenValueParsed;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Test for AesCtrHmacAeadProtoSerialization. */
@RunWith(Theories.class)
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class AesCtrHmacAeadProtoSerializationTest {
  private static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";

  private static final SecretBytes KEY_BYTES_32 = SecretBytes.randomBytes(32);
  private static final ByteString KEY_BYTES_32_AS_BYTE_STRING =
      ByteString.copyFrom(KEY_BYTES_32.toByteArray(InsecureSecretKeyAccess.get()));

  private static final SecretBytes KEY_BYTES_16 = SecretBytes.randomBytes(16);
  private static final ByteString KEY_BYTES_16_AS_BYTE_STRING =
      ByteString.copyFrom(KEY_BYTES_16.toByteArray(InsecureSecretKeyAccess.get()));

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  private static com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat getAesCtrHmacKeyFormatProto(
      int aesCtrKeySizeBytes,
      int hmacKeySizeBytes,
      int ivSizeBytes,
      int tagSizeBytes,
      HashType hashType) {
    return com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat.newBuilder()
        .setAesCtrKeyFormat(
            com.google.crypto.tink.proto.AesCtrKeyFormat.newBuilder()
                .setParams(
                    com.google.crypto.tink.proto.AesCtrParams.newBuilder()
                        .setIvSize(ivSizeBytes)
                        .build())
                .setKeySize(aesCtrKeySizeBytes)
                .build())
        .setHmacKeyFormat(
            com.google.crypto.tink.proto.HmacKeyFormat.newBuilder()
                .setParams(
                    com.google.crypto.tink.proto.HmacParams.newBuilder()
                        .setTagSize(tagSizeBytes)
                        .setHash(hashType)
                        .build())
                .setKeySize(hmacKeySizeBytes)
                .build())
        .build();
  }

  private static com.google.crypto.tink.proto.AesCtrHmacAeadKey getAesCtrHmacKeyProto(
      int version,
      ByteString aesKeyValue,
      ByteString hmacKeyValue,
      int ivSize,
      int tagSizeBytes,
      HashType hashType) {
    return com.google.crypto.tink.proto.AesCtrHmacAeadKey.newBuilder()
        .setVersion(version)
        .setAesCtrKey(
            com.google.crypto.tink.proto.AesCtrKey.newBuilder()
                .setParams(
                    com.google.crypto.tink.proto.AesCtrParams.newBuilder()
                        .setIvSize(ivSize)
                        .build())
                .setKeyValue(aesKeyValue)
                .build())
        .setHmacKey(
            com.google.crypto.tink.proto.HmacKey.newBuilder()
                .setParams(
                    com.google.crypto.tink.proto.HmacParams.newBuilder()
                        .setTagSize(tagSizeBytes)
                        .setHash(hashType)
                        .build())
                .setKeyValue(hmacKeyValue)
                .build())
        .build();
  }

  @BeforeClass
  public static void setUp() throws Exception {
    AesCtrHmacAeadProtoSerialization.register(registry);
  }

  @Test
  public void registerTwice() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    AesCtrHmacAeadProtoSerialization.register(registry);
    AesCtrHmacAeadProtoSerialization.register(registry);
  }

  @Test
  public void serializeParseParameters_noPrefix_sha1_equal() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(32)
            .setTagSizeBytes(13)
            .setIvSizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA1)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
            OutputPrefixType.RAW,
            getAesCtrHmacKeyFormatProto(32, 32, 16, 13, HashType.SHA1));

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_tink_sha224_equal() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(32)
            .setTagSizeBytes(13)
            .setIvSizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA224)
            .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
            OutputPrefixType.TINK,
            getAesCtrHmacKeyFormatProto(32, 32, 16, 13, HashType.SHA224));

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_crunchy_sha256_equal() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(32)
            .setTagSizeBytes(13)
            .setIvSizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.CRUNCHY)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
            OutputPrefixType.CRUNCHY,
            getAesCtrHmacKeyFormatProto(32, 32, 16, 13, HashType.SHA256));
    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_crunchy_sha384_ivSize12_equal() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(32)
            .setTagSizeBytes(13)
            .setIvSizeBytes(12)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA384)
            .setVariant(AesCtrHmacAeadParameters.Variant.CRUNCHY)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
            OutputPrefixType.CRUNCHY,
            getAesCtrHmacKeyFormatProto(16, 32, 12, 13, HashType.SHA384));
    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_tink_sha512_ivSize14_equal() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(13)
            .setIvSizeBytes(14)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA512)
            .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
            OutputPrefixType.TINK,
            getAesCtrHmacKeyFormatProto(32, 16, 14, 13, HashType.SHA512));
    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseKey_noPrefix_sha1_equal() throws Exception {
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.builder()
            .setParameters(
                AesCtrHmacAeadParameters.builder()
                    .setAesKeySizeBytes(32)
                    .setHmacKeySizeBytes(32)
                    .setTagSizeBytes(13)
                    .setIvSizeBytes(16)
                    .setHashType(AesCtrHmacAeadParameters.HashType.SHA1)
                    .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                    .build())
            .setAesKeyBytes(KEY_BYTES_32)
            .setHmacKeyBytes(KEY_BYTES_32)
            .build();
    com.google.crypto.tink.proto.AesCtrHmacAeadKey protoAesCtrHmacAeadKey =
        getAesCtrHmacKeyProto(
            0, KEY_BYTES_32_AS_BYTE_STRING, KEY_BYTES_32_AS_BYTE_STRING, 16, 13, HashType.SHA1);
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
            protoAesCtrHmacAeadKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCtrHmacAeadKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void serializeParseKey_tink_sha224_equal() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(32)
            .setTagSizeBytes(13)
            .setIvSizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA224)
            .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
            .build();
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.builder()
            .setParameters(parameters)
            .setAesKeyBytes(KEY_BYTES_32)
            .setHmacKeyBytes(KEY_BYTES_32)
            .setIdRequirement(123)
            .build();
    com.google.crypto.tink.proto.AesCtrHmacAeadKey protoAesCtrHmacAeadKey =
        getAesCtrHmacKeyProto(
            0, KEY_BYTES_32_AS_BYTE_STRING, KEY_BYTES_32_AS_BYTE_STRING, 16, 13, HashType.SHA224);
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
            protoAesCtrHmacAeadKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 123);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCtrHmacAeadKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void serializeParseKey_crunchy_sha256_equal() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(32)
            .setTagSizeBytes(13)
            .setIvSizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.CRUNCHY)
            .build();
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.builder()
            .setParameters(parameters)
            .setAesKeyBytes(KEY_BYTES_32)
            .setHmacKeyBytes(KEY_BYTES_32)
            .setIdRequirement(123)
            .build();
    com.google.crypto.tink.proto.AesCtrHmacAeadKey protoAesCtrHmacAeadKey =
        getAesCtrHmacKeyProto(
            0, KEY_BYTES_32_AS_BYTE_STRING, KEY_BYTES_32_AS_BYTE_STRING, 16, 13, HashType.SHA256);
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
            protoAesCtrHmacAeadKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.CRUNCHY,
            /* idRequirement= */ 123);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCtrHmacAeadKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void serializeParseKey_crunchy_sha384_ivSize12_equal() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(32)
            .setTagSizeBytes(13)
            .setIvSizeBytes(12)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA384)
            .setVariant(AesCtrHmacAeadParameters.Variant.CRUNCHY)
            .build();
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.builder()
            .setParameters(parameters)
            .setAesKeyBytes(KEY_BYTES_16)
            .setHmacKeyBytes(KEY_BYTES_32)
            .setIdRequirement(123)
            .build();
    com.google.crypto.tink.proto.AesCtrHmacAeadKey protoAesCtrHmacAeadKey =
        getAesCtrHmacKeyProto(
            0, KEY_BYTES_16_AS_BYTE_STRING, KEY_BYTES_32_AS_BYTE_STRING, 12, 13, HashType.SHA384);
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
            protoAesCtrHmacAeadKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.CRUNCHY,
            /* idRequirement= */ 123);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCtrHmacAeadKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void serializeParseKey_tink_sha512_ivSize14_equal() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(16)
            .setTagSizeBytes(13)
            .setIvSizeBytes(14)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA512)
            .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
            .build();
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.builder()
            .setParameters(parameters)
            .setAesKeyBytes(KEY_BYTES_32)
            .setHmacKeyBytes(KEY_BYTES_16)
            .setIdRequirement(123)
            .build();
    com.google.crypto.tink.proto.AesCtrHmacAeadKey protoAesCtrHmacAeadKey =
        getAesCtrHmacKeyProto(
            0, KEY_BYTES_32_AS_BYTE_STRING, KEY_BYTES_16_AS_BYTE_STRING, 14, 13, HashType.SHA512);
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
            protoAesCtrHmacAeadKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 123);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCtrHmacAeadKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void testParseKeys_noAccess_throws() throws Exception {
    com.google.crypto.tink.proto.AesCtrHmacAeadKey protoAesCtrHmacAeadKey =
        getAesCtrHmacKeyProto(
            0, KEY_BYTES_32_AS_BYTE_STRING, KEY_BYTES_32_AS_BYTE_STRING, 16, 13, HashType.SHA512);
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
            protoAesCtrHmacAeadKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 123);
    assertThrows(GeneralSecurityException.class, () -> registry.parseKey(serialization, null));
  }

  @Test
  public void testParseKey_legacy() throws Exception {
    com.google.crypto.tink.proto.AesCtrHmacAeadKey protoAesCtrHmacAeadKey =
        getAesCtrHmacKeyProto(
            0, KEY_BYTES_32_AS_BYTE_STRING, KEY_BYTES_32_AS_BYTE_STRING, 16, 13, HashType.SHA512);
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
            protoAesCtrHmacAeadKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.LEGACY,
            /* idRequirement= */ 1479);
    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(((AesCtrHmacAeadParameters) parsed.getParameters()).getVariant())
        .isEqualTo(AesCtrHmacAeadParameters.Variant.CRUNCHY);
  }

  @Test
  public void testSerializeKeys_noAccess_throws() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(32)
            .setTagSizeBytes(13)
            .setIvSizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA512)
            .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
            .build();
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.builder()
            .setParameters(parameters)
            .setAesKeyBytes(KEY_BYTES_32)
            .setHmacKeyBytes(KEY_BYTES_32)
            .setIdRequirement(123)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.serializeKey(key, ProtoKeySerialization.class, null));
  }

  @DataPoints("invalidParametersSerializations")
  public static final ProtoParametersSerialization[] INVALID_PARAMETERS_SERIALIZATIONS =
      new ProtoParametersSerialization[] {
        // Tag size too small
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            getAesCtrHmacKeyFormatProto(32, 32, 16, 9, HashType.SHA256)),
        // IV size too small
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            getAesCtrHmacKeyFormatProto(32, 32, 11, 13, HashType.SHA256)),
        // Aes key size too small
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            getAesCtrHmacKeyFormatProto(12, 32, 16, 13, HashType.SHA256)),
        // Hmac key size too small
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            getAesCtrHmacKeyFormatProto(32, 12, 16, 13, HashType.SHA256)),
        // Unknown output prefix
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.UNKNOWN_PREFIX,
            getAesCtrHmacKeyFormatProto(32, 32, 16, 13, HashType.SHA256)),
        // Wrong version:
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat.newBuilder()
                .setAesCtrKeyFormat(
                    com.google.crypto.tink.proto.AesCtrKeyFormat.newBuilder()
                        .setParams(
                            com.google.crypto.tink.proto.AesCtrParams.newBuilder()
                                .setIvSize(32)
                                .build())
                        .setKeySize(32)
                        .build())
                .setHmacKeyFormat(
                    com.google.crypto.tink.proto.HmacKeyFormat.newBuilder()
                        // Here is the version
                        .setVersion(1)
                        .setParams(
                            com.google.crypto.tink.proto.HmacParams.newBuilder()
                                .setTagSize(32)
                                .setHash(HashType.SHA256)
                                .build())
                        .setKeySize(32)
                        .build())
                .build()),
        // Proto messages start with a VarInt, which always ends with a byte with most
        // significant bit unset. 0x80 is hence invalid.
        ProtoParametersSerialization.create(
            KeyTemplate.newBuilder()
                .setTypeUrl(TYPE_URL)
                .setOutputPrefixType(OutputPrefixType.RAW)
                .setValue(ByteString.copyFrom(new byte[] {(byte) 0x80}))
                .build()),
      };

  @Theory
  public void testParseInvalidParameters_fails(
      @FromDataPoints("invalidParametersSerializations")
          ProtoParametersSerialization serializedParameters)
      throws Exception {
    assertThrows(
        GeneralSecurityException.class, () -> registry.parseParameters(serializedParameters));
  }

  private static ProtoKeySerialization[] createInvalidKeySerializations() {
    try {
      return new ProtoKeySerialization[] {
        // Bad Version Number (1)
        ProtoKeySerialization.create(
            TYPE_URL,
            getAesCtrHmacKeyProto(
                    1,
                    KEY_BYTES_32_AS_BYTE_STRING,
                    KEY_BYTES_32_AS_BYTE_STRING,
                    16,
                    13,
                    HashType.SHA512)
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            1479),
        // Unknown prefix
        ProtoKeySerialization.create(
            TYPE_URL,
            getAesCtrHmacKeyProto(
                    0,
                    KEY_BYTES_32_AS_BYTE_STRING,
                    KEY_BYTES_32_AS_BYTE_STRING,
                    16,
                    13,
                    HashType.SHA512)
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.UNKNOWN_PREFIX,
            1479),
        // Bad Tag Length (9)
        ProtoKeySerialization.create(
            TYPE_URL,
            getAesCtrHmacKeyProto(
                    0,
                    KEY_BYTES_32_AS_BYTE_STRING,
                    KEY_BYTES_32_AS_BYTE_STRING,
                    16,
                    9,
                    HashType.SHA512)
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            1479),
        // Bad IV Length (11)
        ProtoKeySerialization.create(
            TYPE_URL,
            getAesCtrHmacKeyProto(
                    0,
                    KEY_BYTES_32_AS_BYTE_STRING,
                    KEY_BYTES_32_AS_BYTE_STRING,
                    11,
                    9,
                    HashType.SHA512)
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            1479),
        // Bad Aes Key Length (8)
        ProtoKeySerialization.create(
            TYPE_URL,
            getAesCtrHmacKeyProto(
                    0,
                    ByteString.copyFrom(new byte[8]),
                    KEY_BYTES_32_AS_BYTE_STRING,
                    16,
                    13,
                    HashType.SHA512)
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            1479),
        // Bad Hmac Key Length (8)
        ProtoKeySerialization.create(
            TYPE_URL,
            getAesCtrHmacKeyProto(
                    0,
                    KEY_BYTES_32_AS_BYTE_STRING,
                    ByteString.copyFrom(new byte[8]),
                    16,
                    13,
                    HashType.SHA512)
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            1479),
        // Invalid proto encoding
        ProtoKeySerialization.create(
            TYPE_URL,
            // Proto messages start with a VarInt, which always ends with a byte with most
            // significant bit unset. 0x80 is hence invalid.
            ByteString.copyFrom(new byte[] {(byte) 0x80}),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            1479),
      };
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  @DataPoints("invalidKeySerializations")
  public static final ProtoKeySerialization[] INVALID_KEY_SERIALIZATIONS =
      createInvalidKeySerializations();

  @Theory
  public void testParseInvalidKeys_throws(
      @FromDataPoints("invalidKeySerializations") ProtoKeySerialization serialization)
      throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }
}
