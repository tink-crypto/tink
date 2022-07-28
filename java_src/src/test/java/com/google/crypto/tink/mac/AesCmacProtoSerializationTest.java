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

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.testing.Asserts.assertEqualWhenValueParsed;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.internal.testing.KeyWithSerialization;
import com.google.crypto.tink.internal.testing.ParametersWithSerialization;
import com.google.crypto.tink.proto.AesCmacParams;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
import org.junit.BeforeClass;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Test for AesCmacProtoSerialization. */
@RunWith(Theories.class)
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class AesCmacProtoSerializationTest {
  private static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.AesCmacKey";

  private static final SecretBytes AES_KEY = SecretBytes.randomBytes(32);
  private static final ByteString AES_KEY_AS_BYTE_STRING =
      ByteString.copyFrom(AES_KEY.toByteArray(InsecureSecretKeyAccess.get()));

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  @BeforeClass
  public static void setUp() throws Exception {
    AesCmacProtoSerialization.register(registry);
  }

  static AesCmacParameters createAesCmacParameters(int tagSize, AesCmacParameters.Variant variant) {
    try {
      return AesCmacParameters.createForKeysetWithCryptographicTagSize(tagSize, variant);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  static AesCmacKey createKey(
      int tagSize,
      AesCmacParameters.Variant variant,
      SecretBytes aesKey,
      @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    return AesCmacKey.createForKeyset(
        createAesCmacParameters(tagSize, variant), aesKey, idRequirement);
  }

  static com.google.crypto.tink.proto.AesCmacKeyFormat createProtoFormat(int tagSize) {
    return com.google.crypto.tink.proto.AesCmacKeyFormat.newBuilder()
        .setKeySize(32)
        .setParams(AesCmacParams.newBuilder().setTagSize(tagSize))
        .build();
  }

  static com.google.crypto.tink.proto.AesCmacKey createProtoKey(int tagSize, ByteString aesKey) {
    return com.google.crypto.tink.proto.AesCmacKey.newBuilder()
        .setVersion(0)
        .setKeyValue(aesKey)
        .setParams(AesCmacParams.newBuilder().setTagSize(tagSize))
        .build();
  }

  @DataPoints("validParameters")
  public static final ParametersWithSerialization[] VALID_PARAMETERS =
      new ParametersWithSerialization[] {
        new ParametersWithSerialization(
            createAesCmacParameters(/*tagSize=*/ 16, AesCmacParameters.Variant.TINK),
            ProtoParametersSerialization.create(
                TYPE_URL, OutputPrefixType.TINK, createProtoFormat(16))),
        new ParametersWithSerialization(
            createAesCmacParameters(/*tagSize=*/ 16, AesCmacParameters.Variant.CRUNCHY),
            ProtoParametersSerialization.create(
                TYPE_URL, OutputPrefixType.CRUNCHY, createProtoFormat(16))),
        new ParametersWithSerialization(
            createAesCmacParameters(/*tagSize=*/ 16, AesCmacParameters.Variant.LEGACY),
            ProtoParametersSerialization.create(
                TYPE_URL, OutputPrefixType.LEGACY, createProtoFormat(16))),
        new ParametersWithSerialization(
            createAesCmacParameters(/*tagSize=*/ 16, AesCmacParameters.Variant.NO_PREFIX),
            ProtoParametersSerialization.create(
                TYPE_URL, OutputPrefixType.RAW, createProtoFormat(16))),
        new ParametersWithSerialization(
            createAesCmacParameters(/*tagSize=*/ 10, AesCmacParameters.Variant.TINK),
            ProtoParametersSerialization.create(
                TYPE_URL, OutputPrefixType.TINK, createProtoFormat(10))),
        new ParametersWithSerialization(
            createAesCmacParameters(/*tagSize=*/ 11, AesCmacParameters.Variant.TINK),
            ProtoParametersSerialization.create(
                TYPE_URL, OutputPrefixType.TINK, createProtoFormat(11))),
        new ParametersWithSerialization(
            createAesCmacParameters(/*tagSize=*/ 12, AesCmacParameters.Variant.TINK),
            ProtoParametersSerialization.create(
                TYPE_URL, OutputPrefixType.TINK, createProtoFormat(12))),
        new ParametersWithSerialization(
            createAesCmacParameters(/*tagSize=*/ 13, AesCmacParameters.Variant.TINK),
            ProtoParametersSerialization.create(
                TYPE_URL, OutputPrefixType.TINK, createProtoFormat(13))),
        new ParametersWithSerialization(
            createAesCmacParameters(/*tagSize=*/ 14, AesCmacParameters.Variant.TINK),
            ProtoParametersSerialization.create(
                TYPE_URL, OutputPrefixType.TINK, createProtoFormat(14))),
        new ParametersWithSerialization(
            createAesCmacParameters(/*tagSize=*/ 15, AesCmacParameters.Variant.TINK),
            ProtoParametersSerialization.create(
                TYPE_URL, OutputPrefixType.TINK, createProtoFormat(15))),
        new ParametersWithSerialization(
            createAesCmacParameters(/*tagSize=*/ 11, AesCmacParameters.Variant.NO_PREFIX),
            ProtoParametersSerialization.create(
                TYPE_URL, OutputPrefixType.RAW, createProtoFormat(11))),
      };

  @DataPoints("invalidParameters")
  public static final ProtoParametersSerialization[] INVALID_PARAMETERS =
      new ProtoParametersSerialization[] {
        ProtoParametersSerialization.create(TYPE_URL, OutputPrefixType.RAW, createProtoFormat(9)),
        ProtoParametersSerialization.create(TYPE_URL, OutputPrefixType.RAW, createProtoFormat(7)),
        ProtoParametersSerialization.create(TYPE_URL, OutputPrefixType.RAW, createProtoFormat(17)),
        ProtoParametersSerialization.create(TYPE_URL, OutputPrefixType.RAW, createProtoFormat(19)),
        ProtoParametersSerialization.create(TYPE_URL, OutputPrefixType.RAW, createProtoFormat(32)),
        ProtoParametersSerialization.create(
            TYPE_URL, OutputPrefixType.UNKNOWN_PREFIX, createProtoFormat(16)),
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
  public void testSerializeParameters(
      @FromDataPoints("validParameters") ParametersWithSerialization pair) throws Exception {
    ProtoParametersSerialization serializedParameters =
        registry.serializeParameters(pair.getParameters(), ProtoParametersSerialization.class);

    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCmacKeyFormat.parser(),
        serializedParameters,
        pair.getSerializedParameters());
  }

  @Theory
  public void testParseValidParameters(
      @FromDataPoints("validParameters") ParametersWithSerialization pair) throws Exception {
    Parameters parsed = registry.parseParameters(pair.getSerializedParameters());
    assertThat(parsed).isEqualTo(pair.getParameters());
  }

  @Theory
  public void testParseInvalidParameters_fails(
      @FromDataPoints("invalidParameters") ProtoParametersSerialization serializedParameters)
      throws Exception {
    assertThrows(
        GeneralSecurityException.class, () -> registry.parseParameters(serializedParameters));
  }

  private static KeyWithSerialization[] createValidKeys() {
    try {
      return new KeyWithSerialization[] {
        new KeyWithSerialization(
            createKey(
                /*tagSize=*/ 16, AesCmacParameters.Variant.TINK, AES_KEY, /*idRequirement=*/ 1479),
            ProtoKeySerialization.create(
                TYPE_URL,
                createProtoKey(/*tagSize=*/ 16, AES_KEY_AS_BYTE_STRING).toByteString(),
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.TINK,
                /*idRequirement=*/ 1479)),
        new KeyWithSerialization(
            createKey(16, AesCmacParameters.Variant.CRUNCHY, AES_KEY, 1479),
            ProtoKeySerialization.create(
                TYPE_URL,
                createProtoKey(/*tagSize=*/ 16, AES_KEY_AS_BYTE_STRING).toByteString(),
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.CRUNCHY,
                /*idRequirement=*/ 1479)),
        new KeyWithSerialization(
            createKey(16, AesCmacParameters.Variant.LEGACY, AES_KEY, 1479),
            ProtoKeySerialization.create(
                TYPE_URL,
                createProtoKey(/*tagSize=*/ 16, AES_KEY_AS_BYTE_STRING).toByteString(),
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.LEGACY,
                1479)),
        new KeyWithSerialization(
            createKey(16, AesCmacParameters.Variant.NO_PREFIX, AES_KEY, null),
            ProtoKeySerialization.create(
                TYPE_URL,
                createProtoKey(/*tagSize=*/ 16, AES_KEY_AS_BYTE_STRING).toByteString(),
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.RAW,
                /*idRequirement=*/ null)),
      };
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  private static ProtoKeySerialization[] createInvalidKeys() {
    try {
      return new ProtoKeySerialization[] {
        // Bad Version Number (1)
        ProtoKeySerialization.create(
            TYPE_URL,
            createProtoKey(16, AES_KEY_AS_BYTE_STRING).toBuilder()
                .setVersion(1)
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            1479),
        // Unknown prefix
        ProtoKeySerialization.create(
            TYPE_URL,
            createProtoKey(16, AES_KEY_AS_BYTE_STRING).toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.UNKNOWN_PREFIX,
            1479),
        // Bad Tag Length (9)
        ProtoKeySerialization.create(
            TYPE_URL,
            createProtoKey(9, AES_KEY_AS_BYTE_STRING).toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            1479),
        // Bad Tag Length (17)
        ProtoKeySerialization.create(
            TYPE_URL,
            createProtoKey(17, AES_KEY_AS_BYTE_STRING).toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            1479),
        // Bad Key Length (16)
        ProtoKeySerialization.create(
            TYPE_URL,
            createProtoKey(16, ByteString.copyFrom(new byte[16])).toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            1479),
        // Bad Key Length (31)
        ProtoKeySerialization.create(
            TYPE_URL,
            createProtoKey(16, ByteString.copyFrom(new byte[31])).toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            1479),
        // Bad Key Length (64)
        ProtoKeySerialization.create(
            TYPE_URL,
            createProtoKey(16, ByteString.copyFrom(new byte[64])).toByteString(),
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
            "Wrong type url",
            createProtoKey(16, AES_KEY_AS_BYTE_STRING).toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            1479),
      };
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  @DataPoints("validKeys")
  public static final KeyWithSerialization[] VALID_KEYS = createValidKeys();

  @DataPoints("invalidKeys")
  public static final ProtoKeySerialization[] INVALID_KEYS = createInvalidKeys();

  @Theory
  public void testSerializeKeys(@FromDataPoints("validKeys") KeyWithSerialization pair)
      throws Exception {
    ProtoKeySerialization tinkFormatSerialized =
        registry.serializeKey(
            pair.getKey(), ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCmacKey.parser(),
        tinkFormatSerialized,
        pair.getSerialization());
  }

  @Theory
  public void testParseKeys(@FromDataPoints("validKeys") KeyWithSerialization pair)
      throws Exception {
    Key parsed = registry.parseKey(pair.getSerialization(), InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(pair.getKey())).isTrue();
  }

  @Theory
  public void testSerializeKeys_noAccess_throws(
      @FromDataPoints("validKeys") KeyWithSerialization pair) throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.serializeKey(pair.getKey(), ProtoKeySerialization.class, null));
  }

  @Theory
  public void testParseKeys_noAccess_throws(@FromDataPoints("validKeys") KeyWithSerialization pair)
      throws Exception {
    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(pair.getSerialization(), null));
  }

  @Theory
  public void testParseInvalidKeys_throws(
      @FromDataPoints("invalidKeys") ProtoKeySerialization serialization) throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }
}
