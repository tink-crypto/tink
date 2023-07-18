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

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.testing.Asserts.assertEqualWhenValueParsed;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.HmacParameters;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacParams;
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

/** Test for HmacProtoSerialization. */
@RunWith(Theories.class)
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class HmacProtoSerializationTest {
  private static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.HmacKey";

  private static final SecretBytes KEY_BYTES_42 = SecretBytes.randomBytes(42);
  private static final ByteString KEY_BYTES_42_AS_BYTE_STRING =
      ByteString.copyFrom(KEY_BYTES_42.toByteArray(InsecureSecretKeyAccess.get()));

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  @BeforeClass
  public static void setUp() throws Exception {
    HmacProtoSerialization.register(registry);
  }

  @Test
  public void serializeParseParameters_noPrefix_sha1_equal() throws Exception {
    HmacParameters parameters = HmacParameters.builder()
          .setKeySizeBytes(42)
          .setTagSizeBytes(13)
          .setHashType(HmacParameters.HashType.SHA1)
          .setVariant(HmacParameters.Variant.NO_PREFIX)
          .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.HmacKey",
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.HmacKeyFormat.newBuilder()
                .setKeySize(42)
                .setParams(HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(13))
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.HmacKeyFormat.parser(),
        serialized,
        serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_tink_sha224_equal() throws Exception {
    HmacParameters parameters = HmacParameters.builder()
          .setKeySizeBytes(42)
          .setTagSizeBytes(13)
          .setHashType(HmacParameters.HashType.SHA224)
          .setVariant(HmacParameters.Variant.TINK)
          .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.HmacKey",
            OutputPrefixType.TINK,
            com.google.crypto.tink.proto.HmacKeyFormat.newBuilder()
                .setKeySize(42)
                .setParams(HmacParams.newBuilder().setHash(HashType.SHA224).setTagSize(13))
                .build());
    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.HmacKeyFormat.parser(),
        serialized,
        serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_legacy_sha256_equal() throws Exception {
    HmacParameters parameters = HmacParameters.builder()
          .setKeySizeBytes(42)
          .setTagSizeBytes(13)
          .setHashType(HmacParameters.HashType.SHA256)
          .setVariant(HmacParameters.Variant.LEGACY)
          .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.HmacKey",
            OutputPrefixType.LEGACY,
            com.google.crypto.tink.proto.HmacKeyFormat.newBuilder()
                .setKeySize(42)
                .setParams(HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(13))
                .build());
    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.HmacKeyFormat.parser(),
        serialized,
        serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_crunchy_sha384_equal() throws Exception {
    HmacParameters parameters = HmacParameters.builder()
          .setKeySizeBytes(42)
          .setTagSizeBytes(13)
          .setHashType(HmacParameters.HashType.SHA384)
          .setVariant(HmacParameters.Variant.CRUNCHY)
          .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.HmacKey",
            OutputPrefixType.CRUNCHY,
            com.google.crypto.tink.proto.HmacKeyFormat.newBuilder()
                .setKeySize(42)
                .setParams(HmacParams.newBuilder().setHash(HashType.SHA384).setTagSize(13))
                .build());
    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.HmacKeyFormat.parser(),
        serialized,
        serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_tink_sha512_equal() throws Exception {
    HmacParameters parameters = HmacParameters.builder()
          .setKeySizeBytes(42)
          .setTagSizeBytes(13)
          .setHashType(HmacParameters.HashType.SHA512)
          .setVariant(HmacParameters.Variant.TINK)
          .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.HmacKey",
            OutputPrefixType.TINK,
            com.google.crypto.tink.proto.HmacKeyFormat.newBuilder()
                .setKeySize(42)
                .setParams(HmacParams.newBuilder().setHash(HashType.SHA512).setTagSize(13))
                .build());
    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.HmacKeyFormat.parser(),
        serialized,
        serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseKey_noPrefix_sha1_equal() throws Exception {
    HmacKey key =
        HmacKey.builder()
            .setParameters(
                HmacParameters.builder()
                    .setKeySizeBytes(42)
                    .setTagSizeBytes(13)
                    .setHashType(HmacParameters.HashType.SHA1)
                    .setVariant(HmacParameters.Variant.NO_PREFIX)
                    .build())
            .setKeyBytes(KEY_BYTES_42)
            .build();
    com.google.crypto.tink.proto.HmacKey protoHmacKey =
        com.google.crypto.tink.proto.HmacKey.newBuilder()
            .setVersion(0)
            .setKeyValue(KEY_BYTES_42_AS_BYTE_STRING)
            .setParams(HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(13))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.HmacKey",
            protoHmacKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /*idRequirement=*/ null);

    ProtoKeySerialization serialized =
        registry.serializeKey(
            key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.HmacKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void serializeParseKey_tink_sha224_equal() throws Exception {
    HmacParameters parameters = HmacParameters.builder()
          .setKeySizeBytes(42)
          .setTagSizeBytes(13)
          .setHashType(HmacParameters.HashType.SHA224)
          .setVariant(HmacParameters.Variant.TINK)
          .build();
    HmacKey key = HmacKey.builder()
        .setParameters(parameters)
        .setKeyBytes(KEY_BYTES_42)
        .setIdRequirement(123)
        .build();
    com.google.crypto.tink.proto.HmacKey protoHmacKey =
        com.google.crypto.tink.proto.HmacKey.newBuilder()
            .setVersion(0)
            .setKeyValue(KEY_BYTES_42_AS_BYTE_STRING)
            .setParams(HmacParams.newBuilder().setHash(HashType.SHA224).setTagSize(13))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.HmacKey",
            protoHmacKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /*idRequirement=*/ 123);

    ProtoKeySerialization serialized =
        registry.serializeKey(
            key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.HmacKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void serializeParseKey_legacy_sha256_equal() throws Exception {
    HmacParameters parameters = HmacParameters.builder()
          .setKeySizeBytes(42)
          .setTagSizeBytes(13)
          .setHashType(HmacParameters.HashType.SHA256)
          .setVariant(HmacParameters.Variant.LEGACY)
          .build();
    HmacKey key = HmacKey.builder()
        .setParameters(parameters)
        .setKeyBytes(KEY_BYTES_42)
        .setIdRequirement(123)
        .build();
    com.google.crypto.tink.proto.HmacKey protoHmacKey =
        com.google.crypto.tink.proto.HmacKey.newBuilder()
            .setVersion(0)
            .setKeyValue(KEY_BYTES_42_AS_BYTE_STRING)
            .setParams(HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(13))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.HmacKey",
            protoHmacKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.LEGACY,
            /*idRequirement=*/ 123);

    ProtoKeySerialization serialized =
        registry.serializeKey(
            key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.HmacKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void serializeParseKey_crunchy_sha384_equal() throws Exception {
    HmacParameters parameters = HmacParameters.builder()
          .setKeySizeBytes(42)
          .setTagSizeBytes(13)
          .setHashType(HmacParameters.HashType.SHA384)
          .setVariant(HmacParameters.Variant.CRUNCHY)
          .build();
    HmacKey key = HmacKey.builder()
        .setParameters(parameters)
        .setKeyBytes(KEY_BYTES_42)
        .setIdRequirement(123)
        .build();
    com.google.crypto.tink.proto.HmacKey protoHmacKey =
        com.google.crypto.tink.proto.HmacKey.newBuilder()
            .setVersion(0)
            .setKeyValue(KEY_BYTES_42_AS_BYTE_STRING)
            .setParams(HmacParams.newBuilder().setHash(HashType.SHA384).setTagSize(13))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.HmacKey",
            protoHmacKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.CRUNCHY,
            /*idRequirement=*/ 123);

    ProtoKeySerialization serialized =
        registry.serializeKey(
            key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.HmacKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void serializeParseKey_tink_sha512_equal() throws Exception {
    HmacParameters parameters = HmacParameters.builder()
          .setKeySizeBytes(42)
          .setTagSizeBytes(13)
          .setHashType(HmacParameters.HashType.SHA512)
          .setVariant(HmacParameters.Variant.TINK)
          .build();
    HmacKey key = HmacKey.builder()
        .setParameters(parameters)
        .setKeyBytes(KEY_BYTES_42)
        .setIdRequirement(123)
        .build();
    com.google.crypto.tink.proto.HmacKey protoHmacKey =
        com.google.crypto.tink.proto.HmacKey.newBuilder()
            .setVersion(0)
            .setKeyValue(KEY_BYTES_42_AS_BYTE_STRING)
            .setParams(HmacParams.newBuilder().setHash(HashType.SHA512).setTagSize(13))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.HmacKey",
            protoHmacKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /*idRequirement=*/ 123);

    ProtoKeySerialization serialized =
        registry.serializeKey(
            key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.HmacKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void testParseKeys_noAccess_throws()
      throws Exception {
    com.google.crypto.tink.proto.HmacKey protoHmacKey =
        com.google.crypto.tink.proto.HmacKey.newBuilder()
            .setVersion(0)
            .setKeyValue(KEY_BYTES_42_AS_BYTE_STRING)
            .setParams(HmacParams.newBuilder().setHash(HashType.SHA512).setTagSize(13))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.HmacKey",
            protoHmacKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /*idRequirement=*/ 123);
    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, null));
  }

  @Test
  public void testSerializeKeys_noAccess_throws() throws Exception {
    HmacParameters parameters = HmacParameters.builder()
          .setKeySizeBytes(42)
          .setTagSizeBytes(13)
          .setHashType(HmacParameters.HashType.SHA512)
          .setVariant(HmacParameters.Variant.TINK)
          .build();
    HmacKey key = HmacKey.builder()
        .setParameters(parameters)
        .setKeyBytes(KEY_BYTES_42)
        .setIdRequirement(123)
        .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.serializeKey(key, ProtoKeySerialization.class, null));
  }

  @DataPoints("invalidParametersSerializations")
  public static final ProtoParametersSerialization[] INVALID_PARAMETERS_SERIALIZATIONS =
      new ProtoParametersSerialization[] {
        // tag size too small
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.HmacKeyFormat.newBuilder()
                .setKeySize(42)
                .setParams(HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(9))
                .build()),
        // key size too small
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.HmacKeyFormat.newBuilder()
                .setKeySize(1)
                .setParams(HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(13))
                .build()),
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.HmacKeyFormat.newBuilder()
                .setKeySize(-1)
                .setParams(HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(13))
                .build()),
        // unknown output prefix
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.UNKNOWN_PREFIX,
            com.google.crypto.tink.proto.HmacKeyFormat.newBuilder()
                .setKeySize(42)
                .setParams(HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(13))
                .build()),
        // version 1 is unknown and must be rejected
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.HmacKeyFormat.newBuilder()
                .setVersion(1)
                .setKeySize(42)
                .setParams(HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(13))
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
            com.google.crypto.tink.proto.HmacKey.newBuilder()
                .setVersion(1)
                .setKeyValue(KEY_BYTES_42_AS_BYTE_STRING)
                .setParams(HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(16))
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            1479),
        // Unknown prefix
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.HmacKey.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_42_AS_BYTE_STRING)
                .setParams(HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(16))
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.UNKNOWN_PREFIX,
            1479),
        // Bad Tag Length (9)
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.HmacKey.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_42_AS_BYTE_STRING)
                .setParams(HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(9))
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            1479),
        // Bad Key Length (8)
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.HmacKey.newBuilder()
                .setVersion(0)
                .setKeyValue(ByteString.copyFrom(new byte[8]))
                .setParams(HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(16))
                .build()
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
        // Wrong Type URL -- not sure if this should be tested; this won't even get to the code
        // under test.
        ProtoKeySerialization.create(
            "WrongTypeUrl",
            com.google.crypto.tink.proto.HmacKey.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_42_AS_BYTE_STRING)
                .setParams(HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(16))
                .build()
                .toByteString(),
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
