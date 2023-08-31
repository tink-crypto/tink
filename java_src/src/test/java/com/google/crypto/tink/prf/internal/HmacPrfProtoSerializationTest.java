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

package com.google.crypto.tink.prf.internal;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.testing.Asserts.assertEqualWhenValueParsed;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.prf.HmacPrfKey;
import com.google.crypto.tink.prf.HmacPrfParameters;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
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

@RunWith(Theories.class)
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class HmacPrfProtoSerializationTest {
  private static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.HmacPrfKey";

  private static final SecretBytes KEY_BYTES_16 = SecretBytes.randomBytes(16);
  private static final ByteString KEY_BYTES_16_AS_BYTE_STRING =
      ByteString.copyFrom(KEY_BYTES_16.toByteArray(InsecureSecretKeyAccess.get()));

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  @BeforeClass
  public static void setUp() throws Exception {
    com.google.crypto.tink.prf.internal.HmacPrfProtoSerialization.register(registry);
  }

  public static final class HashType {
    public final HmacPrfParameters.HashType parametersHash;
    public final com.google.crypto.tink.proto.HashType protoHash;

    public HashType(
        HmacPrfParameters.HashType parametersHash,
        com.google.crypto.tink.proto.HashType protoHash) {
      this.parametersHash = parametersHash;
      this.protoHash = protoHash;
    }
  }

  @DataPoints("hashTypes")
  public static final HashType[] HASH_TYPES =
      new HashType[] {
        new HashType(HmacPrfParameters.HashType.SHA1, com.google.crypto.tink.proto.HashType.SHA1),
        new HashType(
            HmacPrfParameters.HashType.SHA224, com.google.crypto.tink.proto.HashType.SHA224),
        new HashType(
            HmacPrfParameters.HashType.SHA256, com.google.crypto.tink.proto.HashType.SHA256),
        new HashType(
            HmacPrfParameters.HashType.SHA384, com.google.crypto.tink.proto.HashType.SHA384),
        new HashType(
            HmacPrfParameters.HashType.SHA512, com.google.crypto.tink.proto.HashType.SHA512),
      };

  @Test
  public void registerTwice() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    com.google.crypto.tink.prf.internal.HmacPrfProtoSerialization.register(registry);
    com.google.crypto.tink.prf.internal.HmacPrfProtoSerialization.register(registry);
  }

  @Theory
  public void serializeAndParseParameters(@FromDataPoints("hashTypes") HashType hashType)
      throws Exception {
    HmacPrfParameters parameters =
        HmacPrfParameters.builder()
            .setKeySizeBytes(16)
            .setHashType(hashType.parametersHash)
            .build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.HmacPrfKeyFormat.newBuilder()
                .setKeySize(16)
                .setParams(
                    com.google.crypto.tink.proto.HmacPrfParams.newBuilder()
                        .setHash(hashType.protoHash)
                        .build())
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.HmacPrfKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Theory
  public void serializeAndParseKey(@FromDataPoints("hashTypes") HashType hashType)
      throws Exception {
    HmacPrfKey key =
        HmacPrfKey.builder()
            .setParameters(
                HmacPrfParameters.builder()
                    .setKeySizeBytes(16)
                    .setHashType(hashType.parametersHash)
                    .build())
            .setKeyBytes(KEY_BYTES_16)
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.HmacPrfKey.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_16_AS_BYTE_STRING)
                .setParams(
                    com.google.crypto.tink.proto.HmacPrfParams.newBuilder()
                        .setHash(hashType.protoHash)
                        .build())
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.HmacPrfKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void testSerializeKey_noAccess_fails() throws Exception {
    HmacPrfKey key =
        HmacPrfKey.builder()
            .setParameters(
                HmacPrfParameters.builder()
                    .setKeySizeBytes(16)
                    .setHashType(HmacPrfParameters.HashType.SHA384)
                    .build())
            .setKeyBytes(KEY_BYTES_16)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.serializeKey(key, ProtoKeySerialization.class, null));
  }

  @Test
  public void testParseKey_noAccess_fails() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.HmacPrfKey.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_16_AS_BYTE_STRING)
                .setParams(
                    com.google.crypto.tink.proto.HmacPrfParams.newBuilder()
                        .setHash(com.google.crypto.tink.proto.HashType.SHA256)
                        .build())
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);
    assertThrows(GeneralSecurityException.class, () -> registry.parseKey(serialization, null));
  }

  @DataPoints("invalidParametersSerializations")
  public static final ProtoParametersSerialization[] INVALID_PARAMETERS_SERIALIZATIONS =
      new ProtoParametersSerialization[] {
        // Invalid type URL.
        ProtoParametersSerialization.create(
            "i.am.a.random.type.url",
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.HmacPrfKeyFormat.newBuilder()
                .setKeySize(16)
                .setParams(
                    com.google.crypto.tink.proto.HmacPrfParams.newBuilder()
                        .setHash(com.google.crypto.tink.proto.HashType.SHA256)
                        .build())
                .build()),
        // Invalid output prefix type.
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.UNKNOWN_PREFIX,
            com.google.crypto.tink.proto.HmacPrfKeyFormat.newBuilder()
                .setKeySize(16)
                .setParams(
                    com.google.crypto.tink.proto.HmacPrfParams.newBuilder()
                        .setHash(com.google.crypto.tink.proto.HashType.SHA256)
                        .build())
                .build()),
        // Key size is too small.
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.HmacPrfKeyFormat.newBuilder()
                .setKeySize(12)
                .setParams(
                    com.google.crypto.tink.proto.HmacPrfParams.newBuilder()
                        .setHash(com.google.crypto.tink.proto.HashType.SHA256)
                        .build())
                .build()),
        // Unknown hash type.
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.HmacPrfKeyFormat.newBuilder()
                .setKeySize(16)
                .setParams(
                    com.google.crypto.tink.proto.HmacPrfParams.newBuilder()
                        .setHash(com.google.crypto.tink.proto.HashType.UNKNOWN_HASH)
                        .build())
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
        // Invalid type URL.
        ProtoKeySerialization.create(
            "i.am.a.random.type.url",
            com.google.crypto.tink.proto.HmacPrfKey.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_16_AS_BYTE_STRING)
                .setParams(
                    com.google.crypto.tink.proto.HmacPrfParams.newBuilder()
                        .setHash(com.google.crypto.tink.proto.HashType.SHA256)
                        .build())
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null),
        // Invalid version.
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.HmacPrfKey.newBuilder()
                .setVersion(1)
                .setKeyValue(KEY_BYTES_16_AS_BYTE_STRING)
                .setParams(
                    com.google.crypto.tink.proto.HmacPrfParams.newBuilder()
                        .setHash(com.google.crypto.tink.proto.HashType.SHA256)
                        .build())
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null),
        // Key is too small.
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.HmacPrfKey.newBuilder()
                .setVersion(0)
                .setKeyValue(ByteString.copyFrom(new byte[12]))
                .setParams(
                    com.google.crypto.tink.proto.HmacPrfParams.newBuilder()
                        .setHash(com.google.crypto.tink.proto.HashType.SHA256)
                        .build())
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null),
        // Unknown hash type.
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.HmacPrfKey.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_16_AS_BYTE_STRING)
                .setParams(
                    com.google.crypto.tink.proto.HmacPrfParams.newBuilder()
                        .setHash(com.google.crypto.tink.proto.HashType.UNKNOWN_HASH)
                        .build())
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null),
        // Invalid proto encoding.
        ProtoKeySerialization.create(
            TYPE_URL,
            // Proto messages start with a VarInt, which always ends with a byte with most
            // significant bit unset. 0x80 is hence invalid.
            ByteString.copyFrom(new byte[] {(byte) 0x80}),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null),
        // Invalid output prefix type.
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.HmacPrfKey.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_16_AS_BYTE_STRING)
                .setParams(
                    com.google.crypto.tink.proto.HmacPrfParams.newBuilder()
                        .setHash(com.google.crypto.tink.proto.HashType.SHA256)
                        .build())
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            123),
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
