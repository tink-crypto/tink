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

/** Test for XChaCha20Poly1305Serialization. */
@RunWith(Theories.class)
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class XChaCha20Poly1305ProtoSerializationTest {
  private static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key";

  private static final SecretBytes KEY_BYTES_32 = SecretBytes.randomBytes(32);
  private static final ByteString KEY_BYTES_32_AS_BYTE_STRING =
      ByteString.copyFrom(KEY_BYTES_32.toByteArray(InsecureSecretKeyAccess.get()));

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  @BeforeClass
  public static void setUp() throws Exception {
    XChaCha20Poly1305ProtoSerialization.register(registry);
  }

  @Test
  public void registerTwice() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    XChaCha20Poly1305ProtoSerialization.register(registry);
    XChaCha20Poly1305ProtoSerialization.register(registry);
  }

  @Test
  public void serializeParseParameters_noPrefix() throws Exception {
    XChaCha20Poly1305Parameters parameters = XChaCha20Poly1305Parameters.create();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key",
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.XChaCha20Poly1305KeyFormat.getDefaultInstance());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.XChaCha20Poly1305KeyFormat.parser(),
        serialized,
        serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_tink() throws Exception {
    XChaCha20Poly1305Parameters parameters =
        XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK);

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key",
            OutputPrefixType.TINK,
            com.google.crypto.tink.proto.XChaCha20Poly1305KeyFormat.getDefaultInstance());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.XChaCha20Poly1305KeyFormat.parser(),
        serialized,
        serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_crunchy() throws Exception {
    XChaCha20Poly1305Parameters parameters =
        XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.CRUNCHY);

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key",
            OutputPrefixType.CRUNCHY,
            com.google.crypto.tink.proto.XChaCha20Poly1305KeyFormat.getDefaultInstance());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.XChaCha20Poly1305KeyFormat.parser(),
        serialized,
        serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseKey_tink() throws Exception {
    XChaCha20Poly1305Key key =
        XChaCha20Poly1305Key.create(XChaCha20Poly1305Parameters.Variant.TINK, KEY_BYTES_32, 123);

    com.google.crypto.tink.proto.XChaCha20Poly1305Key protoXChaCha20Poly1305Key =
        com.google.crypto.tink.proto.XChaCha20Poly1305Key.newBuilder()
            .setVersion(0)
            .setKeyValue(KEY_BYTES_32_AS_BYTE_STRING)
            .build();

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key",
            protoXChaCha20Poly1305Key.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 123);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.XChaCha20Poly1305Key.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void serializeParseKey_crunchy() throws Exception {
    XChaCha20Poly1305Key key =
        XChaCha20Poly1305Key.create(XChaCha20Poly1305Parameters.Variant.CRUNCHY, KEY_BYTES_32, 123);

    com.google.crypto.tink.proto.XChaCha20Poly1305Key protoXChaCha20Poly1305Key =
        com.google.crypto.tink.proto.XChaCha20Poly1305Key.newBuilder()
            .setVersion(0)
            .setKeyValue(KEY_BYTES_32_AS_BYTE_STRING)
            .build();

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key",
            protoXChaCha20Poly1305Key.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.CRUNCHY,
            /* idRequirement= */ 123);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.XChaCha20Poly1305Key.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void testParseKeys_noAccess_throws() throws Exception {
    com.google.crypto.tink.proto.XChaCha20Poly1305Key protoXChaCha20Poly1305Key =
        com.google.crypto.tink.proto.XChaCha20Poly1305Key.newBuilder()
            .setVersion(0)
            .setKeyValue(KEY_BYTES_32_AS_BYTE_STRING)
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key",
            protoXChaCha20Poly1305Key.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 123);
    assertThrows(GeneralSecurityException.class, () -> registry.parseKey(serialization, null));
  }

  @Test
  public void parseKey_legacy() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.XChaCha20Poly1305Key.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_32_AS_BYTE_STRING)
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.LEGACY,
            1479);
    // Legacy keys are parsed to crunchy
    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(((XChaCha20Poly1305Parameters) parsed.getParameters()).getVariant())
        .isEqualTo(XChaCha20Poly1305Parameters.Variant.CRUNCHY);
  }

  @Test
  public void testSerializeKeys_noAccess_throws() throws Exception {
    XChaCha20Poly1305Key key = XChaCha20Poly1305Key.create(KEY_BYTES_32);
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.serializeKey(key, ProtoKeySerialization.class, null));
  }

  @DataPoints("invalidParametersSerializations")
  public static final ProtoParametersSerialization[] INVALID_PARAMETERS_SERIALIZATIONS =
      new ProtoParametersSerialization[] {
        // Unknown output prefix
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.UNKNOWN_PREFIX,
            com.google.crypto.tink.proto.XChaCha20Poly1305KeyFormat.getDefaultInstance()),
        // Wrong version
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.XChaCha20Poly1305KeyFormat.newBuilder()
                .setVersion(1)
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
            com.google.crypto.tink.proto.XChaCha20Poly1305Key.newBuilder()
                .setVersion(1)
                .setKeyValue(KEY_BYTES_32_AS_BYTE_STRING)
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            1479),
        // Unknown prefix
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.XChaCha20Poly1305Key.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_32_AS_BYTE_STRING)
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.UNKNOWN_PREFIX,
            1479),
        // Bad Key Length
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.XChaCha20Poly1305Key.newBuilder()
                .setVersion(0)
                .setKeyValue(ByteString.copyFrom(new byte[16]))
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
