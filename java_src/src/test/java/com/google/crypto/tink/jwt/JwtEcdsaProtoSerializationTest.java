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
import com.google.crypto.tink.internal.BigIntegerEncoding;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.JwtEcdsaAlgorithm;
import com.google.crypto.tink.proto.JwtEcdsaPublicKey.CustomKid;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.protobuf.ByteString;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class JwtEcdsaProtoSerializationTest {
  private static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey";

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  @BeforeClass
  public static void setUp() throws Exception {
    JwtEcdsaProtoSerialization.register(registry);
  }

  // PARAMETERS PARSING ========================================================= PARAMETERS PARSING
  @Test
  public void serializeParseParameters_kidStrategyIsIgnored_works() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.JwtEcdsaKeyFormat.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtEcdsaAlgorithm.ES256)
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtEcdsaKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_kidStrategyBase64_works() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.TINK,
            com.google.crypto.tink.proto.JwtEcdsaKeyFormat.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtEcdsaAlgorithm.ES256)
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtEcdsaKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_kidStrategyIsIgnored_es384_works() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.JwtEcdsaKeyFormat.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtEcdsaAlgorithm.ES384)
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtEcdsaKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_kidStrategyIsIgnored_es512_works() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.JwtEcdsaKeyFormat.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtEcdsaAlgorithm.ES512)
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtEcdsaKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  // INVALID PARAMETERS SERIALIZATIONS =========================== INVALID PARAMETERS SERIALIZATIONS
  @Test
  public void serializeParameters_kidStrategyCustom_cannotBeSerialized_throws() throws Exception {
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.CUSTOM)
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
            com.google.crypto.tink.proto.JwtEcdsaKeyFormat.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtEcdsaAlgorithm.ES512)
                .build());
    assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
  }

  // PUBLIC KEY PARSING ========================================================= PUBLIC KEY PARSING
  @Test
  public void serializeParsePublicKey_es256_kidIgnored_equal() throws Exception {
    // a valid P256 point. Each coordinate is encoded in 32 bytes.
    String hexX = "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287";
    String hexY = "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac";

    JwtEcdsaPublicKey key =
        JwtEcdsaPublicKey.builder()
            .setParameters(
                JwtEcdsaParameters.builder()
                    .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
                    .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                    .build())
            .setPublicPoint(new ECPoint(new BigInteger(hexX, 16), new BigInteger(hexY, 16)))
            .build();
    com.google.crypto.tink.proto.JwtEcdsaPublicKey protoPublicKey =
        com.google.crypto.tink.proto.JwtEcdsaPublicKey.newBuilder()
            .setVersion(0)
            // X and Y are currently serialized with an extra zero at the beginning.
            .setX(ByteString.copyFrom(Hex.decode("00" + hexX)))
            .setY(ByteString.copyFrom(Hex.decode("00" + hexY)))
            .setAlgorithm(JwtEcdsaAlgorithm.ES256)
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.equalsKey(key)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, /* access= */ null);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtEcdsaPublicKey.parser(), serialized, serialization);
  }

  @Test
  public void serializeParsePublicKey_es384_kidIgnored_equal() throws Exception {
    // a valid P384 point. Each coordinate is encoded in 48 bytes.
    String hexX =
        "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64"
            + "DEF8F0EA9055866064A254515480BC13";
    String hexY =
        "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1"
            + "288B231C3AE0D4FE7344FD2533264720";

    JwtEcdsaPublicKey key =
        JwtEcdsaPublicKey.builder()
            .setParameters(
                JwtEcdsaParameters.builder()
                    .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
                    .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                    .build())
            .setPublicPoint(new ECPoint(new BigInteger(hexX, 16), new BigInteger(hexY, 16)))
            .build();
    com.google.crypto.tink.proto.JwtEcdsaPublicKey protoPublicKey =
        com.google.crypto.tink.proto.JwtEcdsaPublicKey.newBuilder()
            .setVersion(0)
            // X and Y are currently serialized with an extra zero at the beginning.
            .setX(ByteString.copyFrom(Hex.decode("00" + hexX)))
            .setY(ByteString.copyFrom(Hex.decode("00" + hexY)))
            .setAlgorithm(JwtEcdsaAlgorithm.ES384)
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.equalsKey(key)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, /* access= */ null);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtEcdsaPublicKey.parser(), serialized, serialization);
  }

  @Test
  public void serializeParsePublicKey_es521_kidIgnored_equal() throws Exception {
    // a valid P521 point, but encoded with leading zeros or truncated zeros.
    String hexXTruncated =
        "685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a949034085433"
            + "4b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2046d";
    String hexYWithLeadingZeros =
        "0000000000000001ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b739884a83"
            + "bde99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302f676";

    JwtEcdsaPublicKey key =
        JwtEcdsaPublicKey.builder()
            .setParameters(
                JwtEcdsaParameters.builder()
                    .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
                    .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                    .build())
            .setPublicPoint(
                new ECPoint(
                    new BigInteger(hexXTruncated, 16), new BigInteger(hexYWithLeadingZeros, 16)))
            .build();
    com.google.crypto.tink.proto.JwtEcdsaPublicKey protoPublicKey =
        com.google.crypto.tink.proto.JwtEcdsaPublicKey.newBuilder()
            .setVersion(0)
            .setX(ByteString.copyFrom(Hex.decode(hexXTruncated)))
            .setY(ByteString.copyFrom(Hex.decode(hexYWithLeadingZeros)))
            .setAlgorithm(JwtEcdsaAlgorithm.ES512)
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.equalsKey(key)).isTrue();

    // X and Y are currently serialized with an extra zero at the beginning. So we expect X and Y to
    // always be encoded in 67 bytes.
    String expectedHexX =
        "00"
            + "00685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a949034085433"
            + "4b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2046d";
    String expectedHexY =
        "00"
            + "01ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b739884a83"
            + "bde99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302f676";
    com.google.crypto.tink.proto.JwtEcdsaPublicKey expectedProtoPublicKey =
        com.google.crypto.tink.proto.JwtEcdsaPublicKey.newBuilder()
            .setVersion(0)
            .setX(ByteString.copyFrom(Hex.decode(expectedHexX)))
            .setY(ByteString.copyFrom(Hex.decode(expectedHexY)))
            .setAlgorithm(JwtEcdsaAlgorithm.ES512)
            .build();
    ProtoKeySerialization expectedSerialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
            expectedProtoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, /* access= */ null);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtEcdsaPublicKey.parser(), serialized, expectedSerialization);
  }

  @Test
  public void serializeParsePublicKey_es256_kidCustom_equal() throws Exception {
    // a valid P256 point. Each coordinate is encoded in 32 bytes.
    String hexX = "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287";
    String hexY = "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac";

    JwtEcdsaPublicKey key =
        JwtEcdsaPublicKey.builder()
            .setParameters(
                JwtEcdsaParameters.builder()
                    .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
                    .setKidStrategy(JwtEcdsaParameters.KidStrategy.CUSTOM)
                    .build())
            .setPublicPoint(new ECPoint(new BigInteger(hexX, 16), new BigInteger(hexY, 16)))
            .setCustomKid("weirdCustomKid")
            .build();
    com.google.crypto.tink.proto.JwtEcdsaPublicKey protoPublicKey =
        com.google.crypto.tink.proto.JwtEcdsaPublicKey.newBuilder()
            .setVersion(0)
            // X and Y are currently serialized with an extra zero at the beginning.
            .setX(ByteString.copyFrom(Hex.decode("00" + hexX)))
            .setY(ByteString.copyFrom(Hex.decode("00" + hexY)))
            .setAlgorithm(JwtEcdsaAlgorithm.ES256)
            .setCustomKid(CustomKid.newBuilder().setValue("weirdCustomKid").build())
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.equalsKey(key)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, /* access= */ null);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtEcdsaPublicKey.parser(), serialized, serialization);
  }

  @Test
  public void serializeParsePublicKey_es256_base64Kid_equal() throws Exception {
    // a valid P256 point. Each coordinate is encoded in 32 bytes.
    String hexX = "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287";
    String hexY = "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac";

    JwtEcdsaPublicKey key =
        JwtEcdsaPublicKey.builder()
            .setParameters(
                JwtEcdsaParameters.builder()
                    .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
                    .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                    .build())
            .setPublicPoint(new ECPoint(new BigInteger(hexX, 16), new BigInteger(hexY, 16)))
            .setIdRequirement(12345)
            .build();
    com.google.crypto.tink.proto.JwtEcdsaPublicKey protoPublicKey =
        com.google.crypto.tink.proto.JwtEcdsaPublicKey.newBuilder()
            .setVersion(0)
            // X and Y are currently serialized with an extra zero at the beginning.
            .setX(ByteString.copyFrom(Hex.decode("00" + hexX)))
            .setY(ByteString.copyFrom(Hex.decode("00" + hexY)))
            .setAlgorithm(JwtEcdsaAlgorithm.ES256)
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 12345);

    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.equalsKey(key)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, /* access= */ null);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtEcdsaPublicKey.parser(), serialized, serialization);
  }

  // INVALID PUBLIC KEY SERIALIZATIONS =========================== INVALID PUBLIC KEY SERIALIZATIONS
  @Test
  public void parsePublicKey_crunchy_cannotBeParsed_throws() throws Exception {
    String hexX = "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287";
    String hexY = "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac";

    com.google.crypto.tink.proto.JwtEcdsaPublicKey protoPublicKey =
        com.google.crypto.tink.proto.JwtEcdsaPublicKey.newBuilder()
            .setVersion(0)
            // X and Y are currently serialized with an extra zero at the beginning.
            .setX(ByteString.copyFrom(Hex.decode("00" + hexX)))
            .setY(ByteString.copyFrom(Hex.decode("00" + hexY)))
            .setAlgorithm(JwtEcdsaAlgorithm.ES256)
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.CRUNCHY,
            /* idRequirement= */ 12345);

    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }

  @Test
  public void parsePublicKey_tinkAndCustomKeyId_throws() throws Exception {
    String hexX = "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287";
    String hexY = "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac";

    com.google.crypto.tink.proto.JwtEcdsaPublicKey protoPublicKey =
        com.google.crypto.tink.proto.JwtEcdsaPublicKey.newBuilder()
            .setVersion(0)
            // X and Y are currently serialized with an extra zero at the beginning.
            .setX(ByteString.copyFrom(Hex.decode("00" + hexX)))
            .setY(ByteString.copyFrom(Hex.decode("00" + hexY)))
            .setAlgorithm(JwtEcdsaAlgorithm.ES256)
            .setCustomKid(CustomKid.newBuilder().setValue("WillNotParseWithRAW").build())
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 12345);

    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }

  @Test
  public void parsePublicKey_wrongVersion_throws() throws Exception {
    String hexX = "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287";
    String hexY = "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac";

    com.google.crypto.tink.proto.JwtEcdsaPublicKey protoPublicKey =
        com.google.crypto.tink.proto.JwtEcdsaPublicKey.newBuilder()
            .setVersion(1)
            // X and Y are currently serialized with an extra zero at the beginning.
            .setX(ByteString.copyFrom(Hex.decode("00" + hexX)))
            .setY(ByteString.copyFrom(Hex.decode("00" + hexY)))
            .setAlgorithm(JwtEcdsaAlgorithm.ES256)
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 12345);

    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }

  @Test
  public void parsePublicKey_unknownAlgorithm_throws() throws Exception {
    String hexX = "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287";
    String hexY = "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac";

    com.google.crypto.tink.proto.JwtEcdsaPublicKey protoPublicKey =
        com.google.crypto.tink.proto.JwtEcdsaPublicKey.newBuilder()
            .setVersion(0)
            // X and Y are currently serialized with an extra zero at the beginning.
            .setX(ByteString.copyFrom(Hex.decode("00" + hexX)))
            .setY(ByteString.copyFrom(Hex.decode("00" + hexY)))
            .setAlgorithm(JwtEcdsaAlgorithm.ES_UNKNOWN)
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 12345);

    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }
  // PRIVATE KEY PARSING ======================================================= PRIVATE KEY PARSING
  @Test
  public void serializeParsePrivateKey_es256_kidIgnored_equal() throws Exception {
    // a valid P256 point. Each coordinate is encoded in 32 bytes.
    String hexX = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
    String hexY = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
    String hexPrivateValue = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
    SecretBigInteger privateValue =
        SecretBigInteger.fromBigInteger(
            BigIntegerEncoding.fromUnsignedBigEndianBytes(Hex.decode(hexPrivateValue)),
            InsecureSecretKeyAccess.get());

    JwtEcdsaPublicKey publicKey =
        JwtEcdsaPublicKey.builder()
            .setParameters(
                JwtEcdsaParameters.builder()
                    .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
                    .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                    .build())
            .setPublicPoint(new ECPoint(new BigInteger(hexX, 16), new BigInteger(hexY, 16)))
            .build();
    JwtEcdsaPrivateKey privateKey = JwtEcdsaPrivateKey.create(publicKey, privateValue);

    com.google.crypto.tink.proto.JwtEcdsaPrivateKey protoPrivateKey =
        com.google.crypto.tink.proto.JwtEcdsaPrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(
                com.google.crypto.tink.proto.JwtEcdsaPublicKey.newBuilder()
                    .setVersion(0)
                    // X and Y are currently serialized with an extra zero at the beginning.
                    .setX(ByteString.copyFrom(Hex.decode("00" + hexX)))
                    .setY(ByteString.copyFrom(Hex.decode("00" + hexY)))
                    .setAlgorithm(JwtEcdsaAlgorithm.ES256))
            .setKeyValue(ByteString.copyFrom(Hex.decode("00" + hexPrivateValue)))
            .build();

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
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
        com.google.crypto.tink.proto.JwtEcdsaPrivateKey.parser(), serialized, serialization);
  }

  @Test
  public void parsePrivateKey_invalidVersion() throws Exception {
    // a valid P256 point. Each coordinate is encoded in 32 bytes.
    String hexX = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
    String hexY = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
    String hexPrivateValue = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";

    com.google.crypto.tink.proto.JwtEcdsaPrivateKey protoPrivateKey =
        com.google.crypto.tink.proto.JwtEcdsaPrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(
                com.google.crypto.tink.proto.JwtEcdsaPublicKey.newBuilder()
                    .setVersion(1)
                    // X and Y are currently serialized with an extra zero at the beginning.
                    .setX(ByteString.copyFrom(Hex.decode("00" + hexX)))
                    .setY(ByteString.copyFrom(Hex.decode("00" + hexY)))
                    .setAlgorithm(JwtEcdsaAlgorithm.ES256))
            .setKeyValue(ByteString.copyFrom(Hex.decode("00" + hexPrivateValue)))
            .build();

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
            protoPrivateKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }

  @Test
  public void serialize_noSecretKeyAccess_throws() throws Exception {
    // a valid P256 point. Each coordinate is encoded in 32 bytes.
    String hexX = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
    String hexY = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
    String hexPrivateValue = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
    SecretBigInteger privateValue =
        SecretBigInteger.fromBigInteger(
            BigIntegerEncoding.fromUnsignedBigEndianBytes(Hex.decode(hexPrivateValue)),
            InsecureSecretKeyAccess.get());

    JwtEcdsaPublicKey publicKey =
        JwtEcdsaPublicKey.builder()
            .setParameters(
                JwtEcdsaParameters.builder()
                    .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
                    .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                    .build())
            .setPublicPoint(new ECPoint(new BigInteger(hexX, 16), new BigInteger(hexY, 16)))
            .build();
    JwtEcdsaPrivateKey privateKey = JwtEcdsaPrivateKey.create(publicKey, privateValue);

    assertThrows(
        GeneralSecurityException.class,
        () -> registry.serializeKey(privateKey, ProtoKeySerialization.class, /* access= */ null));
  }

  @Test
  public void parse_noSecretKeyAccess_throws() throws Exception {
    // a valid P256 point. Each coordinate is encoded in 32 bytes.
    String hexX = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
    String hexY = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
    String hexPrivateValue = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";

    com.google.crypto.tink.proto.JwtEcdsaPrivateKey protoPrivateKey =
        com.google.crypto.tink.proto.JwtEcdsaPrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(
                com.google.crypto.tink.proto.JwtEcdsaPublicKey.newBuilder()
                    .setVersion(0)
                    // X and Y are currently serialized with an extra zero at the beginning.
                    .setX(ByteString.copyFrom(Hex.decode("00" + hexX)))
                    .setY(ByteString.copyFrom(Hex.decode("00" + hexY)))
                    .setAlgorithm(JwtEcdsaAlgorithm.ES256))
            .setKeyValue(ByteString.copyFrom(Hex.decode("00" + hexPrivateValue)))
            .build();

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
            protoPrivateKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
  }
}
