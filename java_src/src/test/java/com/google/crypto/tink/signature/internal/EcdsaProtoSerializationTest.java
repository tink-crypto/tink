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
import com.google.crypto.tink.proto.EcdsaParams;
import com.google.crypto.tink.proto.EcdsaSignatureEncoding;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Test for EcdsaProtoSerialization. */
@RunWith(Theories.class)
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class EcdsaProtoSerializationTest {
  private static final String PUBLIC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.EcdsaPublicKey";
  private static final String PRIVATE_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  @BeforeClass
  public static void setUp() throws Exception {
    EcdsaProtoSerialization.register(registry);
  }

  @Test
  public void serializeParseParameters_ieee_p256_sha256_no_prefix_equal() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.EcdsaKeyFormat.newBuilder()
                .setParams(
                    EcdsaParams.newBuilder()
                        .setHashType(HashType.SHA256)
                        .setCurve(EllipticCurveType.NIST_P256)
                        .setEncoding(EcdsaSignatureEncoding.IEEE_P1363))
                .build());
    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.EcdsaKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_der_p384_sha512_legacy_equal() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
            .setCurveType(EcdsaParameters.CurveType.NIST_P384)
            .setHashType(EcdsaParameters.HashType.SHA512)
            .setVariant(EcdsaParameters.Variant.LEGACY)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
            OutputPrefixType.LEGACY,
            com.google.crypto.tink.proto.EcdsaKeyFormat.newBuilder()
                .setParams(
                    EcdsaParams.newBuilder()
                        .setHashType(HashType.SHA512)
                        .setCurve(EllipticCurveType.NIST_P384)
                        .setEncoding(EcdsaSignatureEncoding.DER))
                .build());
    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.EcdsaKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_ieee_p512_sha384_tink_equal() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P521)
            .setHashType(EcdsaParameters.HashType.SHA512)
            .setVariant(EcdsaParameters.Variant.TINK)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
            OutputPrefixType.TINK,
            com.google.crypto.tink.proto.EcdsaKeyFormat.newBuilder()
                .setParams(
                    EcdsaParams.newBuilder()
                        .setHashType(HashType.SHA512)
                        .setCurve(EllipticCurveType.NIST_P521)
                        .setEncoding(EcdsaSignatureEncoding.IEEE_P1363))
                .build());
    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.EcdsaKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_der_p256_shaP256_crunchy_equal() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.CRUNCHY)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
            OutputPrefixType.CRUNCHY,
            com.google.crypto.tink.proto.EcdsaKeyFormat.newBuilder()
                .setParams(
                    EcdsaParams.newBuilder()
                        .setHashType(HashType.SHA256)
                        .setCurve(EllipticCurveType.NIST_P256)
                        .setEncoding(EcdsaSignatureEncoding.DER))
                .build());
    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.EcdsaKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParsePublicKey_p256_tink_equal() throws Exception {
    // a valid P256 point. Each coordinate is encoded in 32 bytes.
    String hexX = "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287";
    String hexY = "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac";

    EcdsaPublicKey key =
        EcdsaPublicKey.builder()
            .setParameters(
                EcdsaParameters.builder()
                    .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                    .setCurveType(EcdsaParameters.CurveType.NIST_P256)
                    .setHashType(EcdsaParameters.HashType.SHA256)
                    .setVariant(EcdsaParameters.Variant.TINK)
                    .build())
            .setPublicPoint(new ECPoint(new BigInteger(hexX, 16), new BigInteger(hexY, 16)))
            .setIdRequirement(123)
            .build();
    com.google.crypto.tink.proto.EcdsaPublicKey protoPublicKey =
        com.google.crypto.tink.proto.EcdsaPublicKey.newBuilder()
            .setVersion(0)
            // X and Y are currently serialized with an extra zero at the beginning.
            .setX(ByteString.copyFrom(Hex.decode("00" + hexX)))
            .setY(ByteString.copyFrom(Hex.decode("00" + hexY)))
            .setParams(
                EcdsaParams.newBuilder()
                    .setHashType(HashType.SHA256)
                    .setCurve(EllipticCurveType.NIST_P256)
                    .setEncoding(EcdsaSignatureEncoding.IEEE_P1363))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EcdsaPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 123);

    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.equalsKey(key)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, /* access= */ null);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.EcdsaPublicKey.parser(), serialized, serialization);
  }

  @Test
  public void serializeParsePublicKey_p384_no_prefix_equal() throws Exception {
    // a valid P384 point. Each coordinate is encoded in 48 bytes.
    String hexX =
        "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64"
            + "DEF8F0EA9055866064A254515480BC13";
    String hexY =
        "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1"
            + "288B231C3AE0D4FE7344FD2533264720";

    EcdsaPublicKey key =
        EcdsaPublicKey.builder()
            .setParameters(
                EcdsaParameters.builder()
                    .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                    .setCurveType(EcdsaParameters.CurveType.NIST_P384)
                    .setHashType(EcdsaParameters.HashType.SHA384)
                    .setVariant(EcdsaParameters.Variant.NO_PREFIX)
                    .build())
            .setPublicPoint(new ECPoint(new BigInteger(hexX, 16), new BigInteger(hexY, 16)))
            .build();
    com.google.crypto.tink.proto.EcdsaPublicKey protoPublicKey =
        com.google.crypto.tink.proto.EcdsaPublicKey.newBuilder()
            .setVersion(0)
            // X and Y are currently serialized with an extra zero at the beginning.
            .setX(ByteString.copyFrom(Hex.decode("00" + hexX)))
            .setY(ByteString.copyFrom(Hex.decode("00" + hexY)))
            .setParams(
                EcdsaParams.newBuilder()
                    .setHashType(HashType.SHA384)
                    .setCurve(EllipticCurveType.NIST_P384)
                    .setEncoding(EcdsaSignatureEncoding.IEEE_P1363))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EcdsaPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.equalsKey(key)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, /* access= */ null);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.EcdsaPublicKey.parser(), serialized, serialization);
  }

  @Test
  public void parseSerializePublicKey_reencodesNumbersInFixedLengthByteArrays() throws Exception {
    // a valid P521 point, but encoded with leading zeros or truncated zeros.
    String hexXTruncated =
        "685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a949034085433"
            + "4b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2046d";
    String hexYWithLeadingZeros =
        "0000000000000001ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b739884a83"
            + "bde99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302f676";

    com.google.crypto.tink.proto.EcdsaPublicKey protoPublicKey =
        com.google.crypto.tink.proto.EcdsaPublicKey.newBuilder()
            .setVersion(0)
            .setX(ByteString.copyFrom(Hex.decode(hexXTruncated)))
            .setY(ByteString.copyFrom(Hex.decode(hexYWithLeadingZeros)))
            .setParams(
                EcdsaParams.newBuilder()
                    .setHashType(HashType.SHA512)
                    .setCurve(EllipticCurveType.NIST_P521)
                    .setEncoding(EcdsaSignatureEncoding.IEEE_P1363))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EcdsaPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.LEGACY,
            /* idRequirement= */ 123);

    Key key = registry.parseKey(serialization, /* access= */ null);
    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, /* access= */ null);

    com.google.crypto.tink.proto.EcdsaPublicKey protoPublicKeyFromSerialized =
        com.google.crypto.tink.proto.EcdsaPublicKey.parseFrom(
            serialized.getValue(), ExtensionRegistryLite.getEmptyRegistry());

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
    assertThat(protoPublicKeyFromSerialized.getX())
        .isEqualTo(ByteString.copyFrom(Hex.decode(expectedHexX)));
    assertThat(protoPublicKeyFromSerialized.getY())
        .isEqualTo(ByteString.copyFrom(Hex.decode(expectedHexY)));
  }

  @Test
  public void serializedProtoCanBeParsedUsingBigIntegerTwoComplementEncoding() throws Exception {
    String hexX = "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287";
    String hexY = "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac";

    EcdsaPublicKey key =
        EcdsaPublicKey.builder()
            .setParameters(
                EcdsaParameters.builder()
                    .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                    .setCurveType(EcdsaParameters.CurveType.NIST_P256)
                    .setHashType(EcdsaParameters.HashType.SHA256)
                    .setVariant(EcdsaParameters.Variant.TINK)
                    .build())
            .setPublicPoint(new ECPoint(new BigInteger(hexX, 16), new BigInteger(hexY, 16)))
            .setIdRequirement(123)
            .build();

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, /* access= */ null);

    com.google.crypto.tink.proto.EcdsaPublicKey parsedProtoEcdsaPublicKey =
        com.google.crypto.tink.proto.EcdsaPublicKey.parseFrom(
            serialized.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    // parse x and y using BigIntegers two complement encoding.
    assertThat(new BigInteger(parsedProtoEcdsaPublicKey.getX().toByteArray()))
        .isEqualTo(key.getPublicPoint().getAffineX());
    assertThat(new BigInteger(parsedProtoEcdsaPublicKey.getY().toByteArray()))
        .isEqualTo(key.getPublicPoint().getAffineY());
  }

  @Test
  public void serializeParsePrivateKey_p256_tink_equal() throws Exception {
    // a valid P256 private key
    // All values are encoded as 32 bytes.
    String hexX = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
    String hexY = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
    String hexPrivateValue = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";

    EcdsaPublicKey publicKey =
        EcdsaPublicKey.builder()
            .setParameters(
                EcdsaParameters.builder()
                    .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                    .setCurveType(EcdsaParameters.CurveType.NIST_P256)
                    .setHashType(EcdsaParameters.HashType.SHA256)
                    .setVariant(EcdsaParameters.Variant.TINK)
                    .build())
            .setPublicPoint(new ECPoint(new BigInteger(hexX, 16), new BigInteger(hexY, 16)))
            .setIdRequirement(123)
            .build();
    EcdsaPrivateKey privateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(
                SecretBigInteger.fromBigInteger(
                    new BigInteger(hexPrivateValue, 16), InsecureSecretKeyAccess.get()))
            .build();

    com.google.crypto.tink.proto.EcdsaPublicKey protoPublicKey =
        com.google.crypto.tink.proto.EcdsaPublicKey.newBuilder()
            .setVersion(0)
            // X and Y are currently serialized with an extra zero at the beginning.
            .setX(ByteString.copyFrom(Hex.decode("00" + hexX)))
            .setY(ByteString.copyFrom(Hex.decode("00" + hexY)))
            .setParams(
                EcdsaParams.newBuilder()
                    .setHashType(HashType.SHA256)
                    .setCurve(EllipticCurveType.NIST_P256)
                    .setEncoding(EcdsaSignatureEncoding.IEEE_P1363))
            .build();
    com.google.crypto.tink.proto.EcdsaPrivateKey protoPrivateKey =
        com.google.crypto.tink.proto.EcdsaPrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(protoPublicKey)
            // privateValue is currently serialized with an extra zero at the beginning.
            .setKeyValue(ByteString.copyFrom(Hex.decode("00" + hexPrivateValue)))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
            protoPrivateKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            /* idRequirement= */ 123);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(privateKey)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(
            privateKey, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());

    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.EcdsaPublicKey.parser(), serialized, serialization);
  }

  @Test
  public void testParsePrivateKey_noAccess_throws() throws Exception {
    String hexX = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
    String hexY = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
    String hexPrivateValue = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
    com.google.crypto.tink.proto.EcdsaPublicKey protoPublicKey =
        com.google.crypto.tink.proto.EcdsaPublicKey.newBuilder()
            .setVersion(0)
            .setX(ByteString.copyFrom(Hex.decode(hexX)))
            .setY(ByteString.copyFrom(Hex.decode(hexY)))
            .setParams(
                EcdsaParams.newBuilder()
                    .setHashType(HashType.SHA256)
                    .setCurve(EllipticCurveType.NIST_P256)
                    .setEncoding(EcdsaSignatureEncoding.IEEE_P1363))
            .build();
    com.google.crypto.tink.proto.EcdsaPrivateKey protoPrivateKey =
        com.google.crypto.tink.proto.EcdsaPrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(protoPublicKey)
            .setKeyValue(ByteString.copyFrom(Hex.decode(hexPrivateValue)))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
            protoPrivateKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            /* idRequirement= */ 123);
    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
  }

  @Test
  public void testSerializeKeys_noAccess_throws() throws Exception {
    String hexX = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
    String hexY = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
    String hexPrivateValue = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";

    EcdsaPublicKey publicKey =
        EcdsaPublicKey.builder()
            .setParameters(
                EcdsaParameters.builder()
                    .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                    .setCurveType(EcdsaParameters.CurveType.NIST_P256)
                    .setHashType(EcdsaParameters.HashType.SHA256)
                    .setVariant(EcdsaParameters.Variant.TINK)
                    .build())
            .setPublicPoint(new ECPoint(new BigInteger(hexX, 16), new BigInteger(hexY, 16)))
            .setIdRequirement(123)
            .build();
    EcdsaPrivateKey privateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(
                SecretBigInteger.fromBigInteger(
                    new BigInteger(hexPrivateValue, 16), InsecureSecretKeyAccess.get()))
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> registry.serializeKey(privateKey, ProtoKeySerialization.class, /* access= */ null));
  }

  @DataPoints("invalidParametersSerializations")
  public static final ProtoParametersSerialization[] INVALID_PARAMETERS_SERIALIZATIONS =
      new ProtoParametersSerialization[] {
        // invalid hash type
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.EcdsaKeyFormat.newBuilder()
                .setParams(
                    EcdsaParams.newBuilder()
                        .setHashType(HashType.SHA1)
                        .setCurve(EllipticCurveType.NIST_P256)
                        .setEncoding(EcdsaSignatureEncoding.IEEE_P1363))
                .build()),
        // unsupported curve
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.EcdsaKeyFormat.newBuilder()
                .setParams(
                    EcdsaParams.newBuilder()
                        .setHashType(HashType.SHA256)
                        .setCurve(EllipticCurveType.CURVE25519)
                        .setEncoding(EcdsaSignatureEncoding.IEEE_P1363))
                .build()),
        // unknown encoding
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.EcdsaKeyFormat.newBuilder()
                .setParams(
                    EcdsaParams.newBuilder()
                        .setHashType(HashType.SHA256)
                        .setCurve(EllipticCurveType.NIST_P256)
                        .setEncoding(EcdsaSignatureEncoding.UNKNOWN_ENCODING))
                .build()),
        // unknown output prefix
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.UNKNOWN_PREFIX,
            com.google.crypto.tink.proto.EcdsaKeyFormat.newBuilder()
                .setParams(
                    EcdsaParams.newBuilder()
                        .setHashType(HashType.SHA256)
                        .setCurve(EllipticCurveType.NIST_P256)
                        .setEncoding(EcdsaSignatureEncoding.IEEE_P1363))
                .build()),
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
      String hexX = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
      String hexY = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
      return new ProtoKeySerialization[] {
        // Point not on curve
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            com.google.crypto.tink.proto.EcdsaPublicKey.newBuilder()
                .setVersion(1)
                .setX(ByteString.copyFrom(Hex.decode(hexX)))
                .setY(
                    ByteString.copyFrom(
                        Hex.decode(
                            // modified hexY
                            "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462298")))
                .setParams(
                    EcdsaParams.newBuilder()
                        .setHashType(HashType.SHA256)
                        .setCurve(EllipticCurveType.NIST_P256)
                        .setEncoding(EcdsaSignatureEncoding.IEEE_P1363))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            1479),
        // Bad Version Number (1)
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            com.google.crypto.tink.proto.EcdsaPublicKey.newBuilder()
                .setVersion(1)
                .setX(ByteString.copyFrom(Hex.decode(hexX)))
                .setY(ByteString.copyFrom(Hex.decode(hexY)))
                .setParams(
                    EcdsaParams.newBuilder()
                        .setHashType(HashType.SHA256)
                        .setCurve(EllipticCurveType.NIST_P256)
                        .setEncoding(EcdsaSignatureEncoding.IEEE_P1363))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            1479),
        // Unknown prefix
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            com.google.crypto.tink.proto.EcdsaPublicKey.newBuilder()
                .setVersion(0)
                .setX(ByteString.copyFrom(Hex.decode(hexX)))
                .setY(ByteString.copyFrom(Hex.decode(hexY)))
                .setParams(
                    EcdsaParams.newBuilder()
                        .setHashType(HashType.SHA256)
                        .setCurve(EllipticCurveType.NIST_P256)
                        .setEncoding(EcdsaSignatureEncoding.IEEE_P1363))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.UNKNOWN_PREFIX,
            1479),
        // Bad Hash type
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            com.google.crypto.tink.proto.EcdsaPublicKey.newBuilder()
                .setVersion(0)
                .setX(ByteString.copyFrom(Hex.decode(hexX)))
                .setY(ByteString.copyFrom(Hex.decode(hexY)))
                .setParams(
                    EcdsaParams.newBuilder()
                        .setHashType(HashType.UNKNOWN_HASH)
                        .setCurve(EllipticCurveType.NIST_P256)
                        .setEncoding(EcdsaSignatureEncoding.IEEE_P1363))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            1479),
        // Bad curve
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            com.google.crypto.tink.proto.EcdsaPublicKey.newBuilder()
                .setVersion(0)
                .setX(ByteString.copyFrom(Hex.decode(hexX)))
                .setY(ByteString.copyFrom(Hex.decode(hexY)))
                .setParams(
                    EcdsaParams.newBuilder()
                        .setHashType(HashType.SHA256)
                        .setCurve(EllipticCurveType.UNKNOWN_CURVE)
                        .setEncoding(EcdsaSignatureEncoding.IEEE_P1363))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            1479),
        // Bad signature encoding
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            com.google.crypto.tink.proto.EcdsaPublicKey.newBuilder()
                .setVersion(0)
                .setX(ByteString.copyFrom(Hex.decode(hexX)))
                .setY(ByteString.copyFrom(Hex.decode(hexY)))
                .setParams(
                    EcdsaParams.newBuilder()
                        .setHashType(HashType.SHA256)
                        .setCurve(EllipticCurveType.NIST_P256)
                        .setEncoding(EcdsaSignatureEncoding.UNKNOWN_ENCODING))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
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
            com.google.crypto.tink.proto.EcdsaPublicKey.newBuilder()
                .setVersion(0)
                .setX(ByteString.copyFrom(Hex.decode(hexX)))
                .setY(ByteString.copyFrom(Hex.decode(hexY)))
                .setParams(
                    EcdsaParams.newBuilder()
                        .setHashType(HashType.SHA256)
                        .setCurve(EllipticCurveType.NIST_P256)
                        .setEncoding(EcdsaSignatureEncoding.IEEE_P1363))
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
      @FromDataPoints("invalidPublicKeySerializations") ProtoKeySerialization serialization)
      throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }

  private static ProtoKeySerialization[] createInvalidPrivateKeySerializations() {
    try {
      String hexX = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
      String hexY = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
      String hexPrivateValue = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";

      com.google.crypto.tink.proto.EcdsaPublicKey validProtoPublicKey =
          com.google.crypto.tink.proto.EcdsaPublicKey.newBuilder()
              .setVersion(0)
              .setX(ByteString.copyFrom(Hex.decode(hexX)))
              .setY(ByteString.copyFrom(Hex.decode(hexY)))
              .setParams(
                  EcdsaParams.newBuilder()
                      .setHashType(HashType.SHA256)
                      .setCurve(EllipticCurveType.NIST_P256)
                      .setEncoding(EcdsaSignatureEncoding.IEEE_P1363))
              .build();

      return new ProtoKeySerialization[] {
        // Bad private key value
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            com.google.crypto.tink.proto.EcdsaPrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(validProtoPublicKey)
                .setKeyValue(
                    ByteString.copyFrom(
                        Hex.decode(
                            // modified hexPrivateValue
                            "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6720")))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            1479),
        // Bad Version Number (1)
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            com.google.crypto.tink.proto.EcdsaPrivateKey.newBuilder()
                .setVersion(1)
                .setPublicKey(validProtoPublicKey)
                .setKeyValue(ByteString.copyFrom(Hex.decode(hexPrivateValue)))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            1479),
        // Unknown prefix
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            com.google.crypto.tink.proto.EcdsaPrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(validProtoPublicKey)
                .setKeyValue(ByteString.copyFrom(Hex.decode(hexPrivateValue)))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.UNKNOWN_PREFIX,
            1479),
        // Bad Public key (invalid signature encoding)
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            com.google.crypto.tink.proto.EcdsaPrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(
                    com.google.crypto.tink.proto.EcdsaPublicKey.newBuilder()
                        .setVersion(0)
                        .setX(ByteString.copyFrom(Hex.decode(hexX)))
                        .setY(ByteString.copyFrom(Hex.decode(hexY)))
                        .setParams(
                            EcdsaParams.newBuilder()
                                .setHashType(HashType.SHA256)
                                .setCurve(EllipticCurveType.NIST_P256)
                                .setEncoding(EcdsaSignatureEncoding.UNKNOWN_ENCODING))
                        .build())
                .setKeyValue(ByteString.copyFrom(Hex.decode(hexPrivateValue)))
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
            com.google.crypto.tink.proto.EcdsaPrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(validProtoPublicKey)
                .setKeyValue(ByteString.copyFrom(Hex.decode(hexPrivateValue)))
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
      @FromDataPoints("invalidPrivateKeySerializations") ProtoKeySerialization serialization)
      throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }
}
