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

package com.google.crypto.tink.signature.internal;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.testing.Asserts.assertEqualWhenValueParsed;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.Ed25519KeyFormat;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.signature.Ed25519Parameters;
import com.google.crypto.tink.signature.Ed25519Parameters.Variant;
import com.google.crypto.tink.signature.Ed25519PrivateKey;
import com.google.crypto.tink.signature.Ed25519PublicKey;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Test for Ed25519ProtoSerialization. */
@RunWith(Theories.class)
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class Ed25519ProtoSerializationTest {
  private static final String PUBLIC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.Ed25519PublicKey";
  private static final String PRIVATE_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey";

  // Test case from https://www.rfc-editor.org/rfc/rfc8032#page-24
  private static final byte[] secretKey =
      Hex.decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
  private static final byte[] publicKey =
      Hex.decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

  private static final SecretBytes PRIVATE_KEY_BYTES =
      SecretBytes.copyFrom(secretKey, InsecureSecretKeyAccess.get());
  private static final Bytes PUBLIC_KEY_BYTES = Bytes.copyFrom(publicKey);

  private static final ByteString PRIVATE_KEY_BYTE_STRING =
      ByteString.copyFrom(PRIVATE_KEY_BYTES.toByteArray(InsecureSecretKeyAccess.get()));
  private static final ByteString PUBLIC_KEY_BYTE_STRING =
      ByteString.copyFrom(PUBLIC_KEY_BYTES.toByteArray());

  // Creates a helper map with the output prefix types which have id requieremts.
  private static Map<Variant, OutputPrefixType> createVariantsMap() {
    Map<Variant, OutputPrefixType> result = new HashMap<>();
    result.put(Ed25519Parameters.Variant.TINK, OutputPrefixType.TINK);
    result.put(Ed25519Parameters.Variant.CRUNCHY, OutputPrefixType.CRUNCHY);
    result.put(Ed25519Parameters.Variant.LEGACY, OutputPrefixType.LEGACY);
    return Collections.unmodifiableMap(result);
  }

  @DataPoints("variantsMap")
  public static final Set<Map.Entry<Ed25519Parameters.Variant, OutputPrefixType>> variantsMap =
      Collections.unmodifiableSet(createVariantsMap().entrySet());

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  @BeforeClass
  public static void setUp() throws Exception {
    Ed25519ProtoSerialization.register(registry);
  }

  @Test
  public void registerTwice() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    Ed25519ProtoSerialization.register(registry);
    Ed25519ProtoSerialization.register(registry);
  }

  @Test
  public void serializeParseParameters_noPrefix() throws Exception {
    Ed25519Parameters parameters = Ed25519Parameters.create();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey",
            OutputPrefixType.RAW,
            Ed25519KeyFormat.getDefaultInstance());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(Ed25519KeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Theory
  public void serializeParseParameters_otherVariants(
      @FromDataPoints("variantsMap")
          Map.Entry<Ed25519Parameters.Variant, OutputPrefixType> variantsMap)
      throws Exception {
    Ed25519Parameters parameters = Ed25519Parameters.create(variantsMap.getKey());

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey",
            variantsMap.getValue(),
            Ed25519KeyFormat.getDefaultInstance());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(Ed25519KeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParsePublicKey_noPrefix() throws Exception {
    Ed25519PublicKey publicKey = Ed25519PublicKey.create(PUBLIC_KEY_BYTES);

    com.google.crypto.tink.proto.Ed25519PublicKey protoPublicKey =
        com.google.crypto.tink.proto.Ed25519PublicKey.newBuilder()
            .setVersion(0)
            .setKeyValue(PUBLIC_KEY_BYTE_STRING)
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.Ed25519PublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(publicKey)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(
            publicKey, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.Ed25519PublicKey.parser(), serialized, serialization);
  }

  @Theory
  public void serializeParsePublicKey_otherVariants(
      @FromDataPoints("variantsMap")
          Map.Entry<Ed25519Parameters.Variant, OutputPrefixType> variantsMap)
      throws Exception {
    Ed25519PublicKey publicKey =
        Ed25519PublicKey.create(
            variantsMap.getKey(), PUBLIC_KEY_BYTES, /* idRequirement= */ 0x0708090a);

    com.google.crypto.tink.proto.Ed25519PublicKey protoPublicKey =
        com.google.crypto.tink.proto.Ed25519PublicKey.newBuilder()
            .setVersion(0)
            .setKeyValue(PUBLIC_KEY_BYTE_STRING)
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.Ed25519PublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            variantsMap.getValue(),
            /* idRequirement= */ 0x0708090a);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(publicKey)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(
            publicKey, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.Ed25519PublicKey.parser(), serialized, serialization);
  }

  @Test
  public void serializeParsePrivateKey_noPrefix() throws Exception {
    Ed25519PublicKey publicKey = Ed25519PublicKey.create(PUBLIC_KEY_BYTES);
    Ed25519PrivateKey privateKey = Ed25519PrivateKey.create(publicKey, PRIVATE_KEY_BYTES);

    com.google.crypto.tink.proto.Ed25519PublicKey protoPublicKey =
        com.google.crypto.tink.proto.Ed25519PublicKey.newBuilder()
            .setVersion(0)
            .setKeyValue(PUBLIC_KEY_BYTE_STRING)
            .build();

    com.google.crypto.tink.proto.Ed25519PrivateKey protoPrivateKey =
        com.google.crypto.tink.proto.Ed25519PrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(protoPublicKey)
            .setKeyValue(PRIVATE_KEY_BYTE_STRING)
            .build();

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey",
            protoPrivateKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(privateKey)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(
            privateKey, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());

    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.Ed25519PublicKey.parser(), serialized, serialization);
  }

  @Theory
  public void serializeParsePrivateKey_otherVariants(
      @FromDataPoints("variantsMap")
          Map.Entry<Ed25519Parameters.Variant, OutputPrefixType> variantsMap)
      throws Exception {
    Ed25519PublicKey publicKey =
        Ed25519PublicKey.create(
            variantsMap.getKey(), PUBLIC_KEY_BYTES, /* idRequirement= */ 0x0708090a);
    Ed25519PrivateKey privateKey = Ed25519PrivateKey.create(publicKey, PRIVATE_KEY_BYTES);

    com.google.crypto.tink.proto.Ed25519PublicKey protoPublicKey =
        com.google.crypto.tink.proto.Ed25519PublicKey.newBuilder()
            .setVersion(0)
            .setKeyValue(PUBLIC_KEY_BYTE_STRING)
            .build();

    com.google.crypto.tink.proto.Ed25519PrivateKey protoPrivateKey =
        com.google.crypto.tink.proto.Ed25519PrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(protoPublicKey)
            .setKeyValue(PRIVATE_KEY_BYTE_STRING)
            .build();

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey",
            protoPrivateKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            variantsMap.getValue(),
            /* idRequirement= */ 0x0708090a);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(privateKey)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(
            privateKey, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());

    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.Ed25519PublicKey.parser(), serialized, serialization);
  }

  @Test
  public void testParsePrivateKey_noAccess_throws() throws Exception {
    com.google.crypto.tink.proto.Ed25519PublicKey protoPublicKey =
        com.google.crypto.tink.proto.Ed25519PublicKey.newBuilder()
            .setVersion(0)
            .setKeyValue(PUBLIC_KEY_BYTE_STRING)
            .build();

    com.google.crypto.tink.proto.Ed25519PrivateKey protoPrivateKey =
        com.google.crypto.tink.proto.Ed25519PrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(protoPublicKey)
            .setKeyValue(PRIVATE_KEY_BYTE_STRING)
            .build();

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey",
            protoPrivateKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            /* idRequirement= */ 0x708090a);
    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
  }

  @Test
  public void testSerializePrivateKey_noAccess_throws() throws Exception {
    Ed25519PublicKey publicKey = Ed25519PublicKey.create(PUBLIC_KEY_BYTES);
    Ed25519PrivateKey privateKey = Ed25519PrivateKey.create(publicKey, PRIVATE_KEY_BYTES);

    assertThrows(
        GeneralSecurityException.class,
        () -> registry.serializeKey(privateKey, ProtoKeySerialization.class, /* access= */ null));
  }

  @DataPoints("invalidParametersSerializations")
  public static final ProtoParametersSerialization[] INVALID_PARAMETERS_SERIALIZATIONS =
      new ProtoParametersSerialization[] {
        // Unknown output prefix
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.UNKNOWN_PREFIX,
            Ed25519KeyFormat.getDefaultInstance()),
        // Bad Version Number
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.RAW,
            Ed25519KeyFormat.newBuilder().setVersion(1).build()),
        // Proto messages start with a VarInt, which always ends with a byte with most
        // significant bit unset. 0x80 is hence invalid.
        ProtoParametersSerialization.create(
            KeyTemplate.newBuilder()
                .setTypeUrl(PRIVATE_TYPE_URL)
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

  private static ProtoKeySerialization[] createInvalidPublicKeySerializations() {
    try {
      return new ProtoKeySerialization[] {
        // Bad Version Number (1)
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            com.google.crypto.tink.proto.Ed25519PublicKey.newBuilder()
                .setVersion(1)
                .setKeyValue(PUBLIC_KEY_BYTE_STRING)
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            1479),
        // Unknown prefix
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            com.google.crypto.tink.proto.Ed25519PublicKey.newBuilder()
                .setVersion(0)
                .setKeyValue(PUBLIC_KEY_BYTE_STRING)
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.UNKNOWN_PREFIX,
            1479),
        // Invalid proto encoding
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            // Proto messages start with a VarInt, which always ends with a byte with most
            // significant bit unset. 0x80 is hence invalid.
            ByteString.copyFrom(new byte[] {(byte) 0x80}),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            1479),
        // Wrong Type URL
        ProtoKeySerialization.create(
            "WrongTypeUrl",
            com.google.crypto.tink.proto.Ed25519PublicKey.newBuilder()
                .setVersion(0)
                .setKeyValue(PUBLIC_KEY_BYTE_STRING)
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            1479),
      };
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  @DataPoints("invalidPublicKeySerializations")
  public static final ProtoKeySerialization[] INVALID_PUBLIC_KEY_SERIALIZATIONS =
      createInvalidPublicKeySerializations();

  @Theory
  public void testParseInvalidPublicKeys_throws(
      @FromDataPoints("invalidPublicKeySerializations") ProtoKeySerialization serialization) {
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }

  private static ProtoKeySerialization[] createInvalidPrivateKeySerializations() {
    try {
      com.google.crypto.tink.proto.Ed25519PublicKey validProtoPublicKey =
          com.google.crypto.tink.proto.Ed25519PublicKey.newBuilder()
              .setVersion(0)
              .setKeyValue(PUBLIC_KEY_BYTE_STRING)
              .build();

      return new ProtoKeySerialization[] {
        // Bad private key value
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            com.google.crypto.tink.proto.Ed25519PrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(validProtoPublicKey)
                .setKeyValue(
                    ByteString.copyFrom(
                        SecretBytes.randomBytes(32).toByteArray(InsecureSecretKeyAccess.get())))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            1479),
        // Bad Version Number (1)
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            com.google.crypto.tink.proto.Ed25519PrivateKey.newBuilder()
                .setVersion(1)
                .setPublicKey(validProtoPublicKey)
                .setKeyValue(PRIVATE_KEY_BYTE_STRING)
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            1479),
        // Unknown prefix
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            com.google.crypto.tink.proto.Ed25519PrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(validProtoPublicKey)
                .setKeyValue(PRIVATE_KEY_BYTE_STRING)
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.UNKNOWN_PREFIX,
            1479),
        // Invalid Public key
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            com.google.crypto.tink.proto.Ed25519PrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(
                    com.google.crypto.tink.proto.Ed25519PublicKey.newBuilder()
                        .setVersion(0)
                        .setKeyValue(
                            ByteString.copyFrom(
                                SecretBytes.randomBytes(32)
                                    .toByteArray(InsecureSecretKeyAccess.get())))
                        .build())
                .setKeyValue(PRIVATE_KEY_BYTE_STRING)
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            1479),
        // Invalid proto encoding
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            // Proto messages start with a VarInt, which always ends with a byte with most
            // significant bit unset. 0x80 is hence invalid.
            ByteString.copyFrom(new byte[] {(byte) 0x80}),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            1479),
        // Wrong Type URL
        ProtoKeySerialization.create(
            "WrongTypeUrl",
            com.google.crypto.tink.proto.Ed25519PrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(validProtoPublicKey)
                .setKeyValue(PRIVATE_KEY_BYTE_STRING)
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            1479),
      };
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  @DataPoints("invalidPrivateKeySerializations")
  public static final ProtoKeySerialization[] INVALID_PRIVATE_KEY_SERIALIZATIONS =
      createInvalidPrivateKeySerializations();

  @Theory
  public void testParseInvalidPrivateKeys_throws(
      @FromDataPoints("invalidPrivateKeySerializations") ProtoKeySerialization serialization) {
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }
}
