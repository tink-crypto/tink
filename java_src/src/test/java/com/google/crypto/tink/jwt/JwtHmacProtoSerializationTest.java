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

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.testing.Asserts.assertEqualWhenValueParsed;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.JwtHmacAlgorithm;
import com.google.crypto.tink.proto.JwtHmacKey.CustomKid;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.Theories;
import org.junit.runner.RunWith;

/** Test for JwtHmacProtoSerialization. */
@RunWith(Theories.class)
public final class JwtHmacProtoSerializationTest {
  private static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.JwtHmacKey";

  private static final SecretBytes KEY_BYTES_42 = SecretBytes.randomBytes(42);
  private static final ByteString KEY_BYTES_42_AS_BYTE_STRING =
      ByteString.copyFrom(KEY_BYTES_42.toByteArray(InsecureSecretKeyAccess.get()));

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  @BeforeClass
  public static void setUp() throws Exception {
    JwtHmacProtoSerialization.register(registry);
  }

  // PARAMETERS PARSING ========================================================= PARAMETERS PARSING
  @Test
  public void serializeParseParameters_kidStrategyIsIgnored_works() throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(19)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.JwtHmacKeyFormat.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtHmacAlgorithm.HS256)
                .setKeySize(19)
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtHmacKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_kidStrategyIsIgnored_differentKeySize_works()
      throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(21)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.JwtHmacKeyFormat.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtHmacAlgorithm.HS256)
                .setKeySize(21)
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtHmacKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_kidStrategyIsIgnored_differentAlgorithm_works()
      throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(19)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS512)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.JwtHmacKeyFormat.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtHmacAlgorithm.HS512)
                .setKeySize(19)
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtHmacKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_kidStrategyBase64_works() throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(19)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.TINK,
            com.google.crypto.tink.proto.JwtHmacKeyFormat.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtHmacAlgorithm.HS256)
                .setKeySize(19)
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtHmacKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  // INVALID PARAMETERS SERIALIZATIONS =========================== INVALID PARAMETERS SERIALIZATIONS
  @Test
  public void serializeParameters_kidStrategyCustom_cannotBeSerialized_throws() throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(19)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.CUSTOM)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.serializeParameters(parameters, ProtoParametersSerialization.class));
  }

  @Test
  public void parseParameters_crunchy_cannotBeParsed_throws() throws Exception {
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.CRUNCHY,
            com.google.crypto.tink.proto.JwtHmacKeyFormat.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtHmacAlgorithm.HS256)
                .setKeySize(19)
                .build());
    assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
  }

  // KEYS PARSING ===================================================================== KEYS PARSING
  @Test
  public void serializeParseKey_kidStrategyIsIgnored_works() throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(42)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    JwtHmacKey key =
        JwtHmacKey.builder().setParameters(parameters).setKeyBytes(KEY_BYTES_42).build();

    com.google.crypto.tink.proto.JwtHmacKey protoKey =
        com.google.crypto.tink.proto.JwtHmacKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(JwtHmacAlgorithm.HS256)
            .setKeyValue(KEY_BYTES_42_AS_BYTE_STRING)
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtHmacKey",
            protoKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtHmacKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void serializeParseKey_kidStrategyIsIgnored_differentAlgorithm_works() throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(42)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS384)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();
    JwtHmacKey key =
        JwtHmacKey.builder().setParameters(parameters).setKeyBytes(KEY_BYTES_42).build();

    com.google.crypto.tink.proto.JwtHmacKey protoKey =
        com.google.crypto.tink.proto.JwtHmacKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(JwtHmacAlgorithm.HS384)
            .setKeyValue(KEY_BYTES_42_AS_BYTE_STRING)
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtHmacKey",
            protoKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtHmacKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void serializeParseKey_kidStrategyIsCustom_works() throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(42)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS512)
            .setKidStrategy(JwtHmacParameters.KidStrategy.CUSTOM)
            .build();
    JwtHmacKey key =
        JwtHmacKey.builder()
            .setParameters(parameters)
            .setKeyBytes(KEY_BYTES_42)
            .setCustomKid("customKidForThisTest")
            .build();

    com.google.crypto.tink.proto.JwtHmacKey protoKey =
        com.google.crypto.tink.proto.JwtHmacKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(JwtHmacAlgorithm.HS512)
            .setKeyValue(KEY_BYTES_42_AS_BYTE_STRING)
            .setCustomKid(CustomKid.newBuilder().setValue("customKidForThisTest"))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtHmacKey",
            protoKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtHmacKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void serializeParseKey_kidStrategyIsCustom_differentAlgorithm_works() throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(42)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS384)
            .setKidStrategy(JwtHmacParameters.KidStrategy.CUSTOM)
            .build();
    JwtHmacKey key =
        JwtHmacKey.builder()
            .setParameters(parameters)
            .setKeyBytes(KEY_BYTES_42)
            .setCustomKid("customKidForThisTest")
            .build();

    com.google.crypto.tink.proto.JwtHmacKey protoKey =
        com.google.crypto.tink.proto.JwtHmacKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(JwtHmacAlgorithm.HS384)
            .setKeyValue(KEY_BYTES_42_AS_BYTE_STRING)
            .setCustomKid(CustomKid.newBuilder().setValue("customKidForThisTest"))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtHmacKey",
            protoKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtHmacKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void serializeParseKey_kidStrategyIsBase64_works() throws Exception {
    JwtHmacParameters parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(42)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS384)
            .setKidStrategy(JwtHmacParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build();
    JwtHmacKey key =
        JwtHmacKey.builder()
            .setParameters(parameters)
            .setKeyBytes(KEY_BYTES_42)
            .setIdRequirement(10203)
            .build();

    com.google.crypto.tink.proto.JwtHmacKey protoKey =
        com.google.crypto.tink.proto.JwtHmacKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(JwtHmacAlgorithm.HS384)
            .setKeyValue(KEY_BYTES_42_AS_BYTE_STRING)
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtHmacKey",
            protoKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 10203);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtHmacKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  // INVALID KEYS SERIALIZATIONS ======================================= INVALID KEYS SERIALIZATIONS
  @Test
  public void serializeKey_wrongVersion_throws() throws Exception {
    com.google.crypto.tink.proto.JwtHmacKey protoKey =
        com.google.crypto.tink.proto.JwtHmacKey.newBuilder()
            .setVersion(1)
            .setAlgorithm(JwtHmacAlgorithm.HS384)
            .setKeyValue(KEY_BYTES_42_AS_BYTE_STRING)
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtHmacKey",
            protoKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 10203);

    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }

  @Test
  public void serializeKey_unknownAlgorithm_throws() throws Exception {
    com.google.crypto.tink.proto.JwtHmacKey protoKey =
        com.google.crypto.tink.proto.JwtHmacKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(JwtHmacAlgorithm.HS_UNKNOWN)
            .setKeyValue(KEY_BYTES_42_AS_BYTE_STRING)
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtHmacKey",
            protoKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 10203);

    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }

  @Test
  public void serializeKey_tinkKeyWithCustomSet_throws() throws Exception {
    com.google.crypto.tink.proto.JwtHmacKey protoKey =
        com.google.crypto.tink.proto.JwtHmacKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(JwtHmacAlgorithm.HS256)
            .setKeyValue(KEY_BYTES_42_AS_BYTE_STRING)
            .setCustomKid(CustomKid.newBuilder().setValue("customKidForThisTest"))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtHmacKey",
            protoKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 10203);

    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }
}
