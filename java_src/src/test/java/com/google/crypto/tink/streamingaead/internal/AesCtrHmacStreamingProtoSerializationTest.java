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

package com.google.crypto.tink.streamingaead.internal;

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
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.streamingaead.AesCtrHmacStreamingKey;
import com.google.crypto.tink.streamingaead.AesCtrHmacStreamingParameters;
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

/** Test for AesCtrHmacStreamingProtoSerialization. */
@RunWith(Theories.class)
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class AesCtrHmacStreamingProtoSerializationTest {
  private static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey";

  private static final SecretBytes KEY_BYTES_37 = SecretBytes.randomBytes(37);
  private static final ByteString KEY_BYTES_37_AS_BYTE_STRING =
      ByteString.copyFrom(KEY_BYTES_37.toByteArray(InsecureSecretKeyAccess.get()));

  private static final SecretBytes KEY_BYTES_36 = SecretBytes.randomBytes(36);
  private static final ByteString KEY_BYTES_36_AS_BYTE_STRING =
      ByteString.copyFrom(KEY_BYTES_36.toByteArray(InsecureSecretKeyAccess.get()));

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  @BeforeClass
  public static void setUp() throws Exception {
    AesCtrHmacStreamingProtoSerialization.register(registry);
  }

  @Test
  public void registerTwice() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    AesCtrHmacStreamingProtoSerialization.register(registry);
    AesCtrHmacStreamingProtoSerialization.register(registry);
  }

  // PARAMETERS ====================================================================================
  @Test
  public void serializeParseParameters_simple() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(19)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(16)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat.newBuilder()
                .setKeySize(19)
                .setParams(
                    com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                        .setCiphertextSegmentSize(1024 * 1024)
                        .setDerivedKeySize(16)
                        .setHkdfHashType(HashType.SHA256)
                        .setHmacParams(
                            HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16)))
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat.parser(),
        serialized,
        serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_differentKeySize() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(20)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(16)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat.newBuilder()
                .setKeySize(20)
                .setParams(
                    com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                        .setCiphertextSegmentSize(1024 * 1024)
                        .setDerivedKeySize(16)
                        .setHkdfHashType(HashType.SHA256)
                        .setHmacParams(
                            HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16)))
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat.parser(),
        serialized,
        serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_differentDerivedKeySize() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(37)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(16)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat.newBuilder()
                .setKeySize(37)
                .setParams(
                    com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                        .setCiphertextSegmentSize(1024 * 1024)
                        .setDerivedKeySize(32)
                        .setHkdfHashType(HashType.SHA256)
                        .setHmacParams(
                            HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16)))
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat.parser(),
        serialized,
        serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_differentHkdfHashType() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(19)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(16)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat.newBuilder()
                .setKeySize(19)
                .setParams(
                    com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                        .setCiphertextSegmentSize(1024 * 1024)
                        .setDerivedKeySize(16)
                        .setHkdfHashType(HashType.SHA512)
                        .setHmacParams(
                            HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16)))
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat.parser(),
        serialized,
        serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_differentHmacHash() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(19)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacTagSizeBytes(16)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat.newBuilder()
                .setKeySize(19)
                .setParams(
                    com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                        .setCiphertextSegmentSize(1024 * 1024)
                        .setDerivedKeySize(16)
                        .setHkdfHashType(HashType.SHA256)
                        .setHmacParams(
                            HmacParams.newBuilder().setHash(HashType.SHA512).setTagSize(16)))
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat.parser(),
        serialized,
        serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_differentHmacTagSize() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(19)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(15)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat.newBuilder()
                .setKeySize(19)
                .setParams(
                    com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                        .setCiphertextSegmentSize(1024 * 1024)
                        .setDerivedKeySize(16)
                        .setHkdfHashType(HashType.SHA256)
                        .setHmacParams(
                            HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(15)))
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat.parser(),
        serialized,
        serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_differentCiphertextSegmentSizeType() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(19)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(16)
            .setCiphertextSegmentSizeBytes(128 * 1024)
            .build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat.newBuilder()
                .setKeySize(19)
                .setParams(
                    com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                        .setCiphertextSegmentSize(128 * 1024)
                        .setDerivedKeySize(16)
                        .setHkdfHashType(HashType.SHA256)
                        .setHmacParams(
                            HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16)))
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat.parser(),
        serialized,
        serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  /** Test that if "OutputPrefixType" is set to Tink, we just ignore it. */
  @Test
  public void parseParameters_outputPrefixIgnored_tink() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(19)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(16)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.TINK,
            com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat.newBuilder()
                .setKeySize(19)
                .setParams(
                    com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                        .setCiphertextSegmentSize(1024 * 1024)
                        .setDerivedKeySize(16)
                        .setHkdfHashType(HashType.SHA256)
                        .setHmacParams(
                            HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16)))
                .build());

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  /** Test that if "OutputPrefixType" is set to CRUNCHY, we just ignore it. */
  @Test
  public void parseParameters_outputPrefixIgnored_crunchy() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(19)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(16)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.CRUNCHY,
            com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat.newBuilder()
                .setKeySize(19)
                .setParams(
                    com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                        .setCiphertextSegmentSize(1024 * 1024)
                        .setDerivedKeySize(16)
                        .setHkdfHashType(HashType.SHA256)
                        .setHmacParams(
                            HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16)))
                .build());

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void parseParameters_outputPrefixIgnored_legacy() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(19)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(16)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.LEGACY,
            com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat.newBuilder()
                .setKeySize(19)
                .setParams(
                    com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                        .setCiphertextSegmentSize(1024 * 1024)
                        .setDerivedKeySize(16)
                        .setHkdfHashType(HashType.SHA256)
                        .setHmacParams(
                            HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16)))
                .build());

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @DataPoints("invalidParametersSerializations")
  public static final ProtoParametersSerialization[] INVALID_PARAMETERS_SERIALIZATIONS =
      new ProtoParametersSerialization[] {
        // Key size smaller than derived key size
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat.newBuilder()
                .setKeySize(16)
                .setParams(
                    com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                        .setCiphertextSegmentSize(1024 * 1024)
                        .setDerivedKeySize(32)
                        .setHkdfHashType(HashType.SHA256)
                        .setHmacParams(
                            HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16)))
                .build()),
        // Bad hash type
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat.newBuilder()
                .setKeySize(16)
                .setParams(
                    com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                        .setCiphertextSegmentSize(1024 * 1024)
                        .setDerivedKeySize(16)
                        .setHkdfHashType(HashType.SHA384)
                        .setHmacParams(
                            HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16)))
                .build()),
        // Bad derived Key Size
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat.newBuilder()
                .setKeySize(16)
                .setParams(
                    com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                        .setCiphertextSegmentSize(1024 * 1024)
                        .setDerivedKeySize(24)
                        .setHkdfHashType(HashType.SHA256)
                        .setHmacParams(
                            HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16)))
                .build()),
        // Short Tag
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat.newBuilder()
                .setKeySize(16)
                .setParams(
                    com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                        .setCiphertextSegmentSize(1024 * 1024)
                        .setDerivedKeySize(16)
                        .setHkdfHashType(HashType.SHA256)
                        .setHmacParams(
                            HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(9)))
                .build())
      };

  @Theory
  public void testParseInvalidParameters_fails(
      @FromDataPoints("invalidParametersSerializations")
          ProtoParametersSerialization serializedParameters)
      throws Exception {
    assertThrows(
        GeneralSecurityException.class, () -> registry.parseParameters(serializedParameters));
  }

  // KEYS ==========================================================================================
  @Test
  public void serializeParseKey_simple() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(37)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(16)
            .build();

    AesCtrHmacStreamingKey key = AesCtrHmacStreamingKey.create(parameters, KEY_BYTES_37);

    com.google.crypto.tink.proto.AesCtrHmacStreamingKey protoKey =
        com.google.crypto.tink.proto.AesCtrHmacStreamingKey.newBuilder()
            .setVersion(0)
            .setKeyValue(KEY_BYTES_37_AS_BYTE_STRING)
            .setParams(
                com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                    .setCiphertextSegmentSize(1024 * 1024)
                    .setDerivedKeySize(32)
                    .setHkdfHashType(HashType.SHA256)
                    .setHmacParams(HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16)))
            .build();

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
            protoKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCtrHmacStreamingKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void serializeParseKey_differentKeySizeBytes() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(36)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(16)
            .build();

    AesCtrHmacStreamingKey key = AesCtrHmacStreamingKey.create(parameters, KEY_BYTES_36);

    com.google.crypto.tink.proto.AesCtrHmacStreamingKey protoKey =
        com.google.crypto.tink.proto.AesCtrHmacStreamingKey.newBuilder()
            .setVersion(0)
            .setKeyValue(KEY_BYTES_36_AS_BYTE_STRING)
            .setParams(
                com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                    .setCiphertextSegmentSize(1024 * 1024)
                    .setDerivedKeySize(32)
                    .setHkdfHashType(HashType.SHA256)
                    .setHmacParams(HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16)))
            .build();

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
            protoKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCtrHmacStreamingKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void serializeParseKey_differentDerivedKeySize() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(37)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(16)
            .build();

    AesCtrHmacStreamingKey key = AesCtrHmacStreamingKey.create(parameters, KEY_BYTES_37);

    com.google.crypto.tink.proto.AesCtrHmacStreamingKey protoKey =
        com.google.crypto.tink.proto.AesCtrHmacStreamingKey.newBuilder()
            .setVersion(0)
            .setKeyValue(KEY_BYTES_37_AS_BYTE_STRING)
            .setParams(
                com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                    .setCiphertextSegmentSize(1024 * 1024)
                    .setDerivedKeySize(16)
                    .setHkdfHashType(HashType.SHA256)
                    .setHmacParams(HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16)))
            .build();

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
            protoKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCtrHmacStreamingKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void serializeParseKey_differentHkdfHashType() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(37)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(16)
            .build();

    AesCtrHmacStreamingKey key = AesCtrHmacStreamingKey.create(parameters, KEY_BYTES_37);

    com.google.crypto.tink.proto.AesCtrHmacStreamingKey protoKey =
        com.google.crypto.tink.proto.AesCtrHmacStreamingKey.newBuilder()
            .setVersion(0)
            .setKeyValue(KEY_BYTES_37_AS_BYTE_STRING)
            .setParams(
                com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                    .setCiphertextSegmentSize(1024 * 1024)
                    .setDerivedKeySize(32)
                    .setHkdfHashType(HashType.SHA512)
                    .setHmacParams(HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16)))
            .build();

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
            protoKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCtrHmacStreamingKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void serializeParseKey_differentHmacHashType() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(37)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(512 * 1024)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacTagSizeBytes(16)
            .build();

    AesCtrHmacStreamingKey key = AesCtrHmacStreamingKey.create(parameters, KEY_BYTES_37);

    com.google.crypto.tink.proto.AesCtrHmacStreamingKey protoKey =
        com.google.crypto.tink.proto.AesCtrHmacStreamingKey.newBuilder()
            .setVersion(0)
            .setKeyValue(KEY_BYTES_37_AS_BYTE_STRING)
            .setParams(
                com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                    .setCiphertextSegmentSize(512 * 1024)
                    .setDerivedKeySize(32)
                    .setHkdfHashType(HashType.SHA256)
                    .setHmacParams(HmacParams.newBuilder().setHash(HashType.SHA512).setTagSize(16)))
            .build();

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
            protoKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCtrHmacStreamingKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }


  @Test
  public void serializeParseKey_differentHmacTagSize() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(37)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(512 * 1024)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(14)
            .build();

    AesCtrHmacStreamingKey key = AesCtrHmacStreamingKey.create(parameters, KEY_BYTES_37);

    com.google.crypto.tink.proto.AesCtrHmacStreamingKey protoKey =
        com.google.crypto.tink.proto.AesCtrHmacStreamingKey.newBuilder()
            .setVersion(0)
            .setKeyValue(KEY_BYTES_37_AS_BYTE_STRING)
            .setParams(
                com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                    .setCiphertextSegmentSize(512 * 1024)
                    .setDerivedKeySize(32)
                    .setHkdfHashType(HashType.SHA256)
                    .setHmacParams(HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(14)))
            .build();

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
            protoKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCtrHmacStreamingKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }


  @Test
  public void serializeParseKey_differentCiphertextSegmentSize() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(37)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(512 * 1024)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(16)
            .build();

    AesCtrHmacStreamingKey key = AesCtrHmacStreamingKey.create(parameters, KEY_BYTES_37);

    com.google.crypto.tink.proto.AesCtrHmacStreamingKey protoKey =
        com.google.crypto.tink.proto.AesCtrHmacStreamingKey.newBuilder()
            .setVersion(0)
            .setKeyValue(KEY_BYTES_37_AS_BYTE_STRING)
            .setParams(
                com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                    .setCiphertextSegmentSize(512 * 1024)
                    .setDerivedKeySize(32)
                    .setHkdfHashType(HashType.SHA256)
                    .setHmacParams(HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16)))
            .build();

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
            protoKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCtrHmacStreamingKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void parseKey_ignoreOutputPrefixType_crunchy() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(37)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(16)
            .build();

    AesCtrHmacStreamingKey key = AesCtrHmacStreamingKey.create(parameters, KEY_BYTES_37);

    com.google.crypto.tink.proto.AesCtrHmacStreamingKey protoKey =
        com.google.crypto.tink.proto.AesCtrHmacStreamingKey.newBuilder()
            .setVersion(0)
            .setKeyValue(KEY_BYTES_37_AS_BYTE_STRING)
            .setParams(
                com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                    .setCiphertextSegmentSize(1024 * 1024)
                    .setDerivedKeySize(32)
                    .setHkdfHashType(HashType.SHA256)
                    .setHmacParams(HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16)))
            .build();

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
            protoKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.CRUNCHY,
            /* idRequirement= */ 132);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void parseKey_ignoreOutputPrefixType_tink() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(37)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(16)
            .build();

    AesCtrHmacStreamingKey key = AesCtrHmacStreamingKey.create(parameters, KEY_BYTES_37);

    com.google.crypto.tink.proto.AesCtrHmacStreamingKey protoKey =
        com.google.crypto.tink.proto.AesCtrHmacStreamingKey.newBuilder()
            .setVersion(0)
            .setKeyValue(KEY_BYTES_37_AS_BYTE_STRING)
            .setParams(
                com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                    .setCiphertextSegmentSize(1024 * 1024)
                    .setDerivedKeySize(32)
                    .setHkdfHashType(HashType.SHA256)
                    .setHmacParams(HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16)))
            .build();

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
            protoKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 123);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void parseKey_ignoreOutputPrefixType_legacy() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(37)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(16)
            .build();

    AesCtrHmacStreamingKey key = AesCtrHmacStreamingKey.create(parameters, KEY_BYTES_37);

    com.google.crypto.tink.proto.AesCtrHmacStreamingKey protoKey =
        com.google.crypto.tink.proto.AesCtrHmacStreamingKey.newBuilder()
            .setVersion(0)
            .setKeyValue(KEY_BYTES_37_AS_BYTE_STRING)
            .setParams(
                com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                    .setCiphertextSegmentSize(1024 * 1024)
                    .setDerivedKeySize(32)
                    .setHkdfHashType(HashType.SHA256)
                    .setHmacParams(HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16)))
            .build();

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
            protoKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.LEGACY,
            /* idRequirement= */ 123);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  private static ProtoKeySerialization[] createInvalidKeySerializations() {
    try {
      com.google.crypto.tink.proto.AesCtrHmacStreamingKey validKey =
          com.google.crypto.tink.proto.AesCtrHmacStreamingKey.newBuilder()
              .setVersion(0)
              .setKeyValue(KEY_BYTES_37_AS_BYTE_STRING)
              .setParams(
                  com.google.crypto.tink.proto.AesCtrHmacStreamingParams.newBuilder()
                      .setCiphertextSegmentSize(1024 * 1024)
                      .setDerivedKeySize(32)
                      .setHkdfHashType(HashType.SHA256)
                      .setHmacParams(HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16)))
              .build();

      return new ProtoKeySerialization[] {
        // Wrong version
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
            validKey.toBuilder().setVersion(1).build().toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null),
        // Wrong Hash type
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
            validKey.toBuilder()
                .setParams(validKey.getParams().toBuilder().setHkdfHashType(HashType.SHA224))
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null),
        // Wrong Hash type
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
            validKey.toBuilder()
                .setParams(validKey.getParams().toBuilder().setHkdfHashType(HashType.SHA384))
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null),
        // Key Shorter than derivedKeySize
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
            validKey.toBuilder()
                .setKeyValue(KEY_BYTES_37_AS_BYTE_STRING.substring(0, 20))
                .setParams(validKey.getParams().toBuilder().setDerivedKeySize(32))
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null),
        // Short CiphertextSegmentSize
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
            validKey.toBuilder()
                .setParams(validKey.getParams().toBuilder().setCiphertextSegmentSize(24))
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null)
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
