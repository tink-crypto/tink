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

package com.google.crypto.tink.hybrid;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.XChaCha20Poly1305Parameters;
import com.google.crypto.tink.internal.KeyTemplateProtoConverter;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.EcPointFormat;
import com.google.crypto.tink.proto.EciesAeadDemParams;
import com.google.crypto.tink.proto.EciesAeadHkdfKeyFormat;
import com.google.crypto.tink.proto.EciesAeadHkdfParams;
import com.google.crypto.tink.proto.EciesAeadHkdfPrivateKey;
import com.google.crypto.tink.proto.EciesAeadHkdfPublicKey;
import com.google.crypto.tink.proto.EciesHkdfKemParams;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.proto.XChaCha20Poly1305KeyFormat;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.X25519;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link EciesProtoSerialization}. */
@RunWith(Theories.class)
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class EciesProtoSerializationTest {
  private static final String PRIVATE_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";

  private static final Bytes SALT = Bytes.copyFrom(Hex.decode("2023af"));
  private static final Parameters DEM_PARAMETERS =
      exceptionIsBug(() -> XChaCha20Poly1305Parameters.create());

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  private static final class VariantTuple {
    final EciesParameters.Variant variant;
    final OutputPrefixType outputPrefixType;

    VariantTuple(EciesParameters.Variant variant, OutputPrefixType outputPrefixType) {
      this.variant = variant;
      this.outputPrefixType = outputPrefixType;
    }
  }

  @DataPoints("variants")
  public static final VariantTuple[] VARIANTS_TUPLES =
      new VariantTuple[] {
        new VariantTuple(EciesParameters.Variant.NO_PREFIX, OutputPrefixType.RAW),
        new VariantTuple(EciesParameters.Variant.TINK, OutputPrefixType.TINK),
        new VariantTuple(EciesParameters.Variant.CRUNCHY, OutputPrefixType.CRUNCHY),
      };

  private static final EciesAeadHkdfParams createEciesProtoParams(
      EllipticCurveType curveType,
      HashType hashType,
      EcPointFormat pointFormat,
      @Nullable ByteString salt,
      KeyTemplate demKeyTemplate) {
    EciesHkdfKemParams.Builder kemProtoParamsBuilder =
        com.google.crypto.tink.proto.EciesHkdfKemParams.newBuilder()
            .setCurveType(curveType)
            .setHkdfHashType(hashType);

    if (salt != null) {
      kemProtoParamsBuilder.setHkdfSalt(salt);
    }

    EciesHkdfKemParams kemProtoParams = kemProtoParamsBuilder.build();

    EciesAeadDemParams demProtoParams =
        com.google.crypto.tink.proto.EciesAeadDemParams.newBuilder()
            .setAeadDem(demKeyTemplate)
            .build();

    return EciesAeadHkdfParams.newBuilder()
        .setKemParams(kemProtoParams)
        .setDemParams(demProtoParams)
        .setEcPointFormat(pointFormat)
        .build();
  }

  static {
    try {
      AeadConfig.register();
      EciesProtoSerialization.register(registry);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static final KeyTemplate DEM_KEY_TEMPLATE =
      exceptionIsBug(
          () -> KeyTemplateProtoConverter.toProto(KeyTemplates.get("XCHACHA20_POLY1305_RAW")));

  @Test
  public void register_calledTwice_succeedsAndSecondCallHasNoEffect() throws Exception {
    EciesParameters parameters =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(DEM_PARAMETERS)
            .setSalt(SALT)
            .build();

    EciesAeadHkdfParams protoParams =
        createEciesProtoParams(
            EllipticCurveType.NIST_P256,
            HashType.SHA256,
            EcPointFormat.UNCOMPRESSED,
            ByteString.copyFrom(SALT.toByteArray()),
            DEM_KEY_TEMPLATE);
    EciesAeadHkdfKeyFormat format =
        EciesAeadHkdfKeyFormat.newBuilder().setParams(protoParams).build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(PRIVATE_TYPE_URL, OutputPrefixType.RAW, format);

    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    assertThat(registry.hasParserForParameters(serialization)).isFalse();
    assertThat(registry.hasSerializerForParameters(parameters, ProtoParametersSerialization.class))
        .isFalse();

    EciesProtoSerialization.register(registry);

    assertThat(registry.hasParserForParameters(serialization)).isTrue();
    assertThat(registry.hasSerializerForParameters(parameters, ProtoParametersSerialization.class))
        .isTrue();

    EciesProtoSerialization.register(registry);

    assertThat(registry.hasParserForParameters(serialization)).isTrue();
    assertThat(registry.hasSerializerForParameters(parameters, ProtoParametersSerialization.class))
        .isTrue();
  }

  @Theory
  public void serializeParseParameters(@FromDataPoints("variants") VariantTuple variantTuple)
      throws Exception {
    EciesParameters parameters =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setVariant(variantTuple.variant)
            .setDemParameters(DEM_PARAMETERS)
            .setSalt(SALT)
            .build();

    EciesAeadHkdfParams protoParams =
        createEciesProtoParams(
            EllipticCurveType.NIST_P256,
            HashType.SHA256,
            EcPointFormat.UNCOMPRESSED,
            ByteString.copyFrom(SALT.toByteArray()),
            DEM_KEY_TEMPLATE);
    EciesAeadHkdfKeyFormat format =
        EciesAeadHkdfKeyFormat.newBuilder().setParams(protoParams).build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL, variantTuple.outputPrefixType, format);

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertThat(serialized.getKeyTemplate().getTypeUrl())
        .isEqualTo(serialization.getKeyTemplate().getTypeUrl());
    assertThat(serialized.getKeyTemplate().getOutputPrefixType())
        .isEqualTo(serialization.getKeyTemplate().getOutputPrefixType());

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Theory
  public void serializeParseParametersX25519() throws Exception {
    EciesParameters parameters =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.X25519)
            .setHashType(EciesParameters.HashType.SHA256)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(DEM_PARAMETERS)
            .build();

    EciesAeadHkdfParams protoParams =
        createEciesProtoParams(
            EllipticCurveType.CURVE25519,
            HashType.SHA256,
            EcPointFormat.COMPRESSED,
            null,
            DEM_KEY_TEMPLATE);
    EciesAeadHkdfKeyFormat format =
        EciesAeadHkdfKeyFormat.newBuilder().setParams(protoParams).build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(PRIVATE_TYPE_URL, OutputPrefixType.RAW, format);

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertThat(serialized.getKeyTemplate().getTypeUrl())
        .isEqualTo(serialization.getKeyTemplate().getTypeUrl());
    assertThat(serialized.getKeyTemplate().getOutputPrefixType())
        .isEqualTo(serialization.getKeyTemplate().getOutputPrefixType());

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Theory
  public void test_demOutputPrefixTypeIsIgnored_whenParsed() throws Exception {
    EciesAeadHkdfParams protoParams =
        createEciesProtoParams(
            EllipticCurveType.CURVE25519,
            HashType.SHA256,
            EcPointFormat.COMPRESSED,
            null,
            DEM_KEY_TEMPLATE);
    EciesAeadHkdfKeyFormat format =
        EciesAeadHkdfKeyFormat.newBuilder().setParams(protoParams).build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(PRIVATE_TYPE_URL, OutputPrefixType.RAW, format);

    EciesParameters parsed = (EciesParameters) registry.parseParameters(serialization);
    assertThat(parsed.getDemParameters().hasIdRequirement()).isFalse();
  }

  @DataPoints("invalidParametersSerializations")
  public static final ProtoParametersSerialization[] INVALID_PARAMETERS_SERIALIZATIONS =
      new ProtoParametersSerialization[] {
        // Unknown output prefix.
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.UNKNOWN_PREFIX,
            EciesAeadHkdfKeyFormat.newBuilder()
                .setParams(
                    createEciesProtoParams(
                        EllipticCurveType.NIST_P256,
                        HashType.SHA256,
                        EcPointFormat.UNCOMPRESSED,
                        ByteString.copyFrom(SALT.toByteArray()),
                        DEM_KEY_TEMPLATE))
                .build()),
        // Unknown Curve.
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.TINK,
            EciesAeadHkdfKeyFormat.newBuilder()
                .setParams(
                    createEciesProtoParams(
                        EllipticCurveType.UNKNOWN_CURVE,
                        HashType.SHA256,
                        EcPointFormat.UNCOMPRESSED,
                        ByteString.copyFrom(SALT.toByteArray()),
                        DEM_KEY_TEMPLATE))
                .build()),
        // CURVE25519 with UNCOMPRESSED.
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.TINK,
            EciesAeadHkdfKeyFormat.newBuilder()
                .setParams(
                    createEciesProtoParams(
                        EllipticCurveType.CURVE25519,
                        HashType.SHA256,
                        EcPointFormat.UNCOMPRESSED,
                        ByteString.copyFrom(SALT.toByteArray()),
                        DEM_KEY_TEMPLATE))
                .build()),
        // Unknown HashType.
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.TINK,
            EciesAeadHkdfKeyFormat.newBuilder()
                .setParams(
                    createEciesProtoParams(
                        EllipticCurveType.NIST_P256,
                        HashType.UNKNOWN_HASH,
                        EcPointFormat.UNCOMPRESSED,
                        ByteString.copyFrom(SALT.toByteArray()),
                        DEM_KEY_TEMPLATE))
                .build()),
        // Unknown Point Format.
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.TINK,
            EciesAeadHkdfKeyFormat.newBuilder()
                .setParams(
                    createEciesProtoParams(
                        EllipticCurveType.NIST_P256,
                        HashType.SHA256,
                        EcPointFormat.UNKNOWN_FORMAT,
                        ByteString.copyFrom(SALT.toByteArray()),
                        DEM_KEY_TEMPLATE))
                .build()),
        // Bad dem key template Type URL.
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.TINK,
            EciesAeadHkdfKeyFormat.newBuilder()
                .setParams(
                    createEciesProtoParams(
                        EllipticCurveType.NIST_P256,
                        HashType.SHA256,
                        EcPointFormat.UNCOMPRESSED,
                        ByteString.copyFrom(SALT.toByteArray()),
                        KeyTemplate.newBuilder()
                            .setTypeUrl("Non Existent Type Url")
                            .setValue(
                                XChaCha20Poly1305KeyFormat.newBuilder()
                                    .setVersion(0)
                                    .build()
                                    .toByteString())
                            .setOutputPrefixType(OutputPrefixType.RAW)
                            .build()))
                .build()),
        // Bad dem key template value.
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.TINK,
            EciesAeadHkdfKeyFormat.newBuilder()
                .setParams(
                    createEciesProtoParams(
                        EllipticCurveType.NIST_P256,
                        HashType.SHA256,
                        EcPointFormat.UNCOMPRESSED,
                        ByteString.copyFrom(SALT.toByteArray()),
                        KeyTemplate.newBuilder()
                            .setTypeUrl(
                                "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key")
                            .setValue(ByteString.copyFrom(new byte[] {(byte) 0x80}))
                            .setOutputPrefixType(OutputPrefixType.RAW)
                            .build()))
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
  public void parseInvalidParameters_fails(
      @FromDataPoints("invalidParametersSerializations")
          ProtoParametersSerialization serializedParameters)
      throws Exception {
    assertThrows(
        GeneralSecurityException.class, () -> registry.parseParameters(serializedParameters));
  }

  // PUBLIC KEY SERIALIZATION ======================================================================
  private static EciesAeadHkdfParams validParamsForCurve(EllipticCurveType curveType)
      throws GeneralSecurityException {
    EciesHkdfKemParams kemParams =
        EciesHkdfKemParams.newBuilder()
            .setCurveType(curveType)
            .setHkdfHashType(HashType.SHA256)
            .setHkdfSalt(ByteString.copyFrom(SALT.toByteArray()))
            .build();
    EciesAeadDemParams demParams =
        EciesAeadDemParams.newBuilder().setAeadDem(DEM_KEY_TEMPLATE).build();
    return EciesAeadHkdfParams.newBuilder()
        .setKemParams(kemParams)
        .setDemParams(demParams)
        .setEcPointFormat(com.google.crypto.tink.proto.EcPointFormat.COMPRESSED)
        .build();
  }

  @Test
  public void serializeParsePublicKey_p256_tink_equal() throws Exception {
    String pointXHex = "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287";
    String pointYHex = "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac";
    ECPoint someP256PublicPoint =
        new ECPoint(new BigInteger(pointXHex, 16), new BigInteger(pointYHex, 16));

    // Java object
    EciesParameters parameters =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
            .setVariant(EciesParameters.Variant.TINK)
            .setDemParameters(DEM_PARAMETERS)
            .setSalt(SALT)
            .build();
    EciesPublicKey publicKey =
        EciesPublicKey.createForNistCurve(parameters, someP256PublicPoint, 101);

    // Proto object
    EciesAeadHkdfPublicKey protoPublicKey =
        EciesAeadHkdfPublicKey.newBuilder()
            .setVersion(0)
            .setParams(
                validParamsForCurve(com.google.crypto.tink.proto.EllipticCurveType.NIST_P256))
            .setX(ByteString.copyFrom(Hex.decode("00" + pointXHex)))
            .setY(ByteString.copyFrom(Hex.decode("00" + pointYHex)))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 101);

    // Comparison
    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.getParameters()).isEqualTo(publicKey.getParameters());
    assertThat(parsed.equalsKey(publicKey)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(publicKey, ProtoKeySerialization.class, /* access= */ null);

    assertThat(serialized.getKeyMaterialType()).isEqualTo(serialization.getKeyMaterialType());
    assertThat(serialized.getOutputPrefixType()).isEqualTo(serialization.getOutputPrefixType());
    assertThat(serialized.getIdRequirementOrNull())
        .isEqualTo(serialization.getIdRequirementOrNull());
    assertThat(serialized.getTypeUrl()).isEqualTo(serialization.getTypeUrl());
  }

  @Test
  public void serializeParsePublicKey_p256_crunchy_equal() throws Exception {
    String pointXHex = "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287";
    String pointYHex = "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac";
    ECPoint someP256PublicPoint =
        new ECPoint(new BigInteger(pointXHex, 16), new BigInteger(pointYHex, 16));

    // Java object
    EciesParameters parameters =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
            .setVariant(EciesParameters.Variant.CRUNCHY)
            .setDemParameters(DEM_PARAMETERS)
            .setSalt(SALT)
            .build();
    EciesPublicKey publicKey =
        EciesPublicKey.createForNistCurve(parameters, someP256PublicPoint, 101);

    // Proto object
    EciesAeadHkdfPublicKey protoPublicKey =
        EciesAeadHkdfPublicKey.newBuilder()
            .setVersion(0)
            .setParams(validParamsForCurve(EllipticCurveType.NIST_P256))
            .setX(ByteString.copyFrom(Hex.decode("00" + pointXHex)))
            .setY(ByteString.copyFrom(Hex.decode("00" + pointYHex)))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.CRUNCHY,
            /* idRequirement= */ 101);

    // Comparison
    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.getParameters()).isEqualTo(publicKey.getParameters());
    assertThat(parsed.equalsKey(publicKey)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(publicKey, ProtoKeySerialization.class, /* access= */ null);

    assertThat(serialized.getKeyMaterialType()).isEqualTo(serialization.getKeyMaterialType());
    assertThat(serialized.getOutputPrefixType()).isEqualTo(serialization.getOutputPrefixType());
    assertThat(serialized.getIdRequirementOrNull())
        .isEqualTo(serialization.getIdRequirementOrNull());
    assertThat(serialized.getTypeUrl()).isEqualTo(serialization.getTypeUrl());
  }

  @Test
  public void parsePublicKey_p256_legacy_equal() throws Exception {
    String pointXHex = "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287";
    String pointYHex = "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac";
    ECPoint someP256PublicPoint =
        new ECPoint(new BigInteger(pointXHex, 16), new BigInteger(pointYHex, 16));

    // Java object
    EciesParameters parameters =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
            .setVariant(EciesParameters.Variant.CRUNCHY)
            .setDemParameters(DEM_PARAMETERS)
            .setSalt(SALT)
            .build();
    EciesPublicKey publicKey =
        EciesPublicKey.createForNistCurve(parameters, someP256PublicPoint, 101);

    // Proto object
    EciesAeadHkdfPublicKey protoPublicKey =
        EciesAeadHkdfPublicKey.newBuilder()
            .setVersion(0)
            .setParams(validParamsForCurve(EllipticCurveType.NIST_P256))
            .setX(ByteString.copyFrom(Hex.decode("00" + pointXHex)))
            .setY(ByteString.copyFrom(Hex.decode("00" + pointYHex)))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.LEGACY,
            /* idRequirement= */ 101);

    // Comparison
    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.getParameters()).isEqualTo(publicKey.getParameters());
    assertThat(parsed.equalsKey(publicKey)).isTrue();
  }

  @Test
  public void serializeParsePublicKey_p384_tink_equal() throws Exception {
    String pointXHex =
        "a7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27fe7513272"
            + "734466b400091adbf2d68c58e0c50066";
    String pointYHex =
        "ac68f19f2e1cb879aed43a9969b91a0839c4c38a49749b661efedf243451915e"
            + "d0905a32b060992b468c64766fc8437a";

    // Java object
    EciesParameters parameters =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P384)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
            .setVariant(EciesParameters.Variant.TINK)
            .setDemParameters(DEM_PARAMETERS)
            .setSalt(SALT)
            .build();
    EciesPublicKey publicKey =
        EciesPublicKey.createForNistCurve(
            parameters,
            new ECPoint(new BigInteger(pointXHex, 16), new BigInteger(pointYHex, 16)),
            101);

    // Proto object
    EciesAeadHkdfPublicKey protoPublicKey =
        EciesAeadHkdfPublicKey.newBuilder()
            .setVersion(0)
            .setParams(
                validParamsForCurve(com.google.crypto.tink.proto.EllipticCurveType.NIST_P384))
            .setX(ByteString.copyFrom(Hex.decode("00" + pointXHex)))
            .setY(ByteString.copyFrom(Hex.decode("00" + pointYHex)))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 101);

    // Comparison
    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.getParameters()).isEqualTo(publicKey.getParameters());
    assertThat(parsed.equalsKey(publicKey)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(publicKey, ProtoKeySerialization.class, /* access= */ null);

    assertThat(serialized.getKeyMaterialType()).isEqualTo(serialization.getKeyMaterialType());
    assertThat(serialized.getOutputPrefixType()).isEqualTo(serialization.getOutputPrefixType());
    assertThat(serialized.getIdRequirementOrNull())
        .isEqualTo(serialization.getIdRequirementOrNull());
    assertThat(serialized.getTypeUrl()).isEqualTo(serialization.getTypeUrl());
  }

  @Test
  public void serializeParsePublicKey_p521_tink_equal() throws Exception {
    String pointXHex =
        "00685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a9490340"
            + "854334b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2"
            + "046d";
    String pointYHex =
        "01ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b7398"
            + "84a83bde99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302"
            + "f676";
    ECPoint someP521PublicPoint =
        new ECPoint(new BigInteger(pointXHex, 16), new BigInteger(pointYHex, 16));

    // Java object
    EciesParameters parameters =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P521)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
            .setVariant(EciesParameters.Variant.TINK)
            .setDemParameters(DEM_PARAMETERS)
            .setSalt(SALT)
            .build();
    EciesPublicKey publicKey =
        EciesPublicKey.createForNistCurve(parameters, someP521PublicPoint, 101);

    // Proto object
    EciesAeadHkdfPublicKey protoPublicKey =
        EciesAeadHkdfPublicKey.newBuilder()
            .setVersion(0)
            .setParams(
                validParamsForCurve(com.google.crypto.tink.proto.EllipticCurveType.NIST_P521))
            .setX(ByteString.copyFrom(Hex.decode("00" + pointXHex)))
            .setY(ByteString.copyFrom(Hex.decode("00" + pointYHex)))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 101);

    // Comparison
    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.getParameters()).isEqualTo(publicKey.getParameters());
    assertThat(parsed.equalsKey(publicKey)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(publicKey, ProtoKeySerialization.class, /* access= */ null);

    assertThat(serialized.getKeyMaterialType()).isEqualTo(serialization.getKeyMaterialType());
    assertThat(serialized.getOutputPrefixType()).isEqualTo(serialization.getOutputPrefixType());
    assertThat(serialized.getIdRequirementOrNull())
        .isEqualTo(serialization.getIdRequirementOrNull());
    assertThat(serialized.getTypeUrl()).isEqualTo(serialization.getTypeUrl());
  }

  @Test
  public void parsePublicKey_parsingIgnoresZeroes_works() throws Exception {
    String pointXHex =
        "0000000000685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a9490340"
            + "854334b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2"
            + "046d";
    String pointYHex =
        "0000000001ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b7398"
            + "84a83bde99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302"
            + "f676";
    ECPoint someP521PublicPoint =
        new ECPoint(new BigInteger(pointXHex, 16), new BigInteger(pointYHex, 16));

    // Java object
    EciesParameters parameters =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P521)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
            .setVariant(EciesParameters.Variant.TINK)
            .setDemParameters(DEM_PARAMETERS)
            .setSalt(SALT)
            .build();
    EciesPublicKey publicKey =
        EciesPublicKey.createForNistCurve(parameters, someP521PublicPoint, 101);

    // Proto object
    EciesAeadHkdfPublicKey protoPublicKey =
        EciesAeadHkdfPublicKey.newBuilder()
            .setVersion(0)
            .setParams(
                validParamsForCurve(com.google.crypto.tink.proto.EllipticCurveType.NIST_P521))
            .setX(ByteString.copyFrom(Hex.decode("00" + pointXHex)))
            .setY(ByteString.copyFrom(Hex.decode("00" + pointYHex)))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 101);

    // Comparison
    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.getParameters()).isEqualTo(publicKey.getParameters());
    assertThat(parsed.equalsKey(publicKey)).isTrue();
  }

  @Test
  public void serializeParsePublicKey_x25519_equal() throws Exception {
    Bytes publicPointBytes = Bytes.copyFrom(X25519.publicFromPrivate(X25519.generatePrivateKey()));

    // Java object
    EciesParameters parameters =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.X25519)
            .setHashType(EciesParameters.HashType.SHA256)
            .setVariant(EciesParameters.Variant.TINK)
            .setDemParameters(DEM_PARAMETERS)
            .setSalt(SALT)
            .build();
    EciesPublicKey publicKey =
        EciesPublicKey.createForCurveX25519(parameters, publicPointBytes, 101);

    // Proto object
    EciesAeadHkdfPublicKey protoPublicKey =
        EciesAeadHkdfPublicKey.newBuilder()
            .setVersion(0)
            .setParams(validParamsForCurve(EllipticCurveType.CURVE25519))
            .setX(ByteString.copyFrom(publicPointBytes.toByteArray()))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 101);

    // Comparison
    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.getParameters()).isEqualTo(publicKey.getParameters());
    assertThat(parsed.equalsKey(publicKey)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(publicKey, ProtoKeySerialization.class, /* access= */ null);

    assertThat(serialized.getKeyMaterialType()).isEqualTo(serialization.getKeyMaterialType());
    assertThat(serialized.getOutputPrefixType()).isEqualTo(serialization.getOutputPrefixType());
    assertThat(serialized.getIdRequirementOrNull())
        .isEqualTo(serialization.getIdRequirementOrNull());
    assertThat(serialized.getTypeUrl()).isEqualTo(serialization.getTypeUrl());
  }

  private static ProtoKeySerialization[] createInvalidPublicKeySerializations() {
    try {
      String pointXHex = "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287";
      String pointYHex = "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac";

      return new ProtoKeySerialization[] {
        // Point not on curve.
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey",
            EciesAeadHkdfPublicKey.newBuilder()
                .setVersion(0)
                .setParams(validParamsForCurve(EllipticCurveType.NIST_P256))
                // pointXHex + 1
                .setX(
                    ByteString.copyFrom(
                        Hex.decode(
                            "00700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d288")))
                .setY(ByteString.copyFrom(Hex.decode("00" + pointYHex)))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 101),
        // Bad version
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey",
            EciesAeadHkdfPublicKey.newBuilder()
                .setVersion(1)
                .setParams(validParamsForCurve(EllipticCurveType.NIST_P256))
                .setX(ByteString.copyFrom(Hex.decode("00" + pointXHex)))
                .setY(ByteString.copyFrom(Hex.decode("00" + pointYHex)))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 101),
        // X25519 Curve with Y set
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey",
            EciesAeadHkdfPublicKey.newBuilder()
                .setVersion(0)
                .setParams(validParamsForCurve(EllipticCurveType.CURVE25519))
                .setX(ByteString.copyFrom(Random.randBytes(32)))
                .setY(ByteString.copyFrom(Random.randBytes(32)))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 101),
        // X25519 Curve with EC Point Format uncompressed
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey",
            EciesAeadHkdfPublicKey.newBuilder()
                .setVersion(0)
                .setParams(
                    validParamsForCurve(EllipticCurveType.CURVE25519).toBuilder()
                        .setEcPointFormat(EcPointFormat.UNCOMPRESSED)
                        .build())
                .setX(ByteString.copyFrom(Random.randBytes(32)))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 101),
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

  // PRIVATE KEY SERIALIZATION =====================================================================
  @Test
  public void serializeParseNistPrivateKey_works() throws Exception {
    String hexX = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
    String hexY = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
    String hexPrivateValue = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";

    // Java object
    EciesParameters parameters =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
            .setVariant(EciesParameters.Variant.TINK)
            .setDemParameters(DEM_PARAMETERS)
            .setSalt(SALT)
            .build();
    EciesPublicKey publicKey =
        EciesPublicKey.createForNistCurve(
            parameters, new ECPoint(new BigInteger(hexX, 16), new BigInteger(hexY, 16)), 101);
    EciesPrivateKey privateKey =
        EciesPrivateKey.createForNistCurve(
            publicKey,
            SecretBigInteger.fromBigInteger(
                new BigInteger(hexPrivateValue, 16), InsecureSecretKeyAccess.get()));

    // Proto object
    EciesAeadHkdfPublicKey protoPublicKey =
        EciesAeadHkdfPublicKey.newBuilder()
            .setVersion(0)
            .setParams(
                validParamsForCurve(com.google.crypto.tink.proto.EllipticCurveType.NIST_P256))
            .setX(ByteString.copyFrom(Hex.decode("00" + hexX)))
            .setY(ByteString.copyFrom(Hex.decode("00" + hexY)))
            .build();
    EciesAeadHkdfPrivateKey protoPrivateKey =
        EciesAeadHkdfPrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(protoPublicKey)
            // privateValue is currently serialized with an extra zero at the beginning.
            .setKeyValue(ByteString.copyFrom(Hex.decode("00" + hexPrivateValue)))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
            protoPrivateKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            /* idRequirement= */ 101);

    // Comparison
    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(privateKey)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(
            privateKey, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());

    assertThat(serialized.getKeyMaterialType()).isEqualTo(serialization.getKeyMaterialType());
    assertThat(serialized.getOutputPrefixType()).isEqualTo(serialization.getOutputPrefixType());
    assertThat(serialized.getIdRequirementOrNull())
        .isEqualTo(serialization.getIdRequirementOrNull());
    assertThat(serialized.getTypeUrl()).isEqualTo(serialization.getTypeUrl());
  }

  @Test
  public void serializeParseX25519PrivateKey_works() throws Exception {
    byte[] privateKeyBytes = X25519.generatePrivateKey();
    byte[] publicKeyBytes = X25519.publicFromPrivate(privateKeyBytes);

    // Java object
    EciesParameters parameters =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.X25519)
            .setHashType(EciesParameters.HashType.SHA256)
            .setVariant(EciesParameters.Variant.TINK)
            .setDemParameters(DEM_PARAMETERS)
            .setSalt(SALT)
            .build();
    EciesPublicKey publicKey =
        EciesPublicKey.createForCurveX25519(parameters, Bytes.copyFrom(publicKeyBytes), 101);
    EciesPrivateKey privateKey =
        EciesPrivateKey.createForCurveX25519(
            publicKey, SecretBytes.copyFrom(privateKeyBytes, InsecureSecretKeyAccess.get()));

    // Proto object
    EciesAeadHkdfPublicKey protoPublicKey =
        EciesAeadHkdfPublicKey.newBuilder()
            .setVersion(0)
            .setParams(validParamsForCurve(EllipticCurveType.CURVE25519))
            .setX(ByteString.copyFrom(publicKeyBytes))
            .build();
    EciesAeadHkdfPrivateKey protoPrivateKey =
        EciesAeadHkdfPrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(protoPublicKey)
            .setKeyValue(ByteString.copyFrom(privateKeyBytes))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
            protoPrivateKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            /* idRequirement= */ 101);

    // Comparison
    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(privateKey)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(
            privateKey, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());

    assertThat(serialized.getKeyMaterialType()).isEqualTo(serialization.getKeyMaterialType());
    assertThat(serialized.getOutputPrefixType()).isEqualTo(serialization.getOutputPrefixType());
    assertThat(serialized.getIdRequirementOrNull())
        .isEqualTo(serialization.getIdRequirementOrNull());
    assertThat(serialized.getTypeUrl()).isEqualTo(serialization.getTypeUrl());
  }

  @Test
  public void testParsePrivateKey_noAccess_throws() throws Exception {
    String hexX = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
    String hexY = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
    String hexPrivateValue = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";

    // Proto object
    EciesAeadHkdfPublicKey protoPublicKey =
        EciesAeadHkdfPublicKey.newBuilder()
            .setVersion(0)
            .setParams(
                validParamsForCurve(com.google.crypto.tink.proto.EllipticCurveType.NIST_P256))
            .setX(ByteString.copyFrom(Hex.decode("00" + hexX)))
            .setY(ByteString.copyFrom(Hex.decode("00" + hexY)))
            .build();
    EciesAeadHkdfPrivateKey protoPrivateKey =
        EciesAeadHkdfPrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(protoPublicKey)
            // privateValue is currently serialized with an extra zero at the beginning.
            .setKeyValue(ByteString.copyFrom(Hex.decode("00" + hexPrivateValue)))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
            protoPrivateKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            /* idRequirement= */ 101);
    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
  }

  @Test
  public void testSerializeKeys_noAccess_throws() throws Exception {
    String hexX = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
    String hexY = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
    String hexPrivateValue = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";

    EciesParameters parameters =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
            .setVariant(EciesParameters.Variant.TINK)
            .setDemParameters(DEM_PARAMETERS)
            .setSalt(SALT)
            .build();
    EciesPublicKey publicKey =
        EciesPublicKey.createForNistCurve(
            parameters, new ECPoint(new BigInteger(hexX, 16), new BigInteger(hexY, 16)), 101);
    EciesPrivateKey privateKey =
        EciesPrivateKey.createForNistCurve(
            publicKey,
            SecretBigInteger.fromBigInteger(
                new BigInteger(hexPrivateValue, 16), InsecureSecretKeyAccess.get()));

    assertThrows(
        GeneralSecurityException.class,
        () -> registry.serializeKey(privateKey, ProtoKeySerialization.class, /* access= */ null));
  }

  private static ProtoKeySerialization[] createInvalidPrivateKeySerializations() {
    try {
      String hexX = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
      String hexY = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
      String hexPrivateValue = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";

      EciesAeadHkdfPublicKey validProtoPublicKey =
          EciesAeadHkdfPublicKey.newBuilder()
              .setVersion(0)
              .setParams(validParamsForCurve(EllipticCurveType.NIST_P256))
              .setX(ByteString.copyFrom(Hex.decode("00" + hexX)))
              .setY(ByteString.copyFrom(Hex.decode("00" + hexY)))
              .build();

      return new ProtoKeySerialization[] {
        // Bad private key value
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
            EciesAeadHkdfPrivateKey.newBuilder()
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
            /* idRequirement= */ 101),
        // Bad version
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
            EciesAeadHkdfPrivateKey.newBuilder()
                .setVersion(1)
                .setPublicKey(validProtoPublicKey)
                .setKeyValue(ByteString.copyFrom(Hex.decode(hexPrivateValue)))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            /* idRequirement= */ 101),
        // Unknown prefix
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
            EciesAeadHkdfPrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(validProtoPublicKey)
                .setKeyValue(ByteString.copyFrom(Hex.decode(hexPrivateValue)))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.UNKNOWN_PREFIX,
            /* idRequirement= */ 101),
        // Bad Public Key (X25519 Curve with EC Point Format uncompressed)
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
            EciesAeadHkdfPrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(
                    EciesAeadHkdfPublicKey.newBuilder()
                        .setVersion(0)
                        .setParams(
                            validParamsForCurve(EllipticCurveType.CURVE25519).toBuilder()
                                .setEcPointFormat(EcPointFormat.UNCOMPRESSED)
                                .build())
                        .setX(ByteString.copyFrom(Random.randBytes(32)))
                        .build())
                .setKeyValue(ByteString.copyFrom(Random.randBytes(32)))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 101),
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
      @FromDataPoints("invalidPublicKeySerializations") ProtoKeySerialization serialization)
      throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }
}
