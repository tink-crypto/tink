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
import static com.google.crypto.tink.internal.testing.Asserts.assertEqualWhenValueParsed;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.XChaCha20Poly1305Parameters;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.EcPointFormat;
import com.google.crypto.tink.proto.EciesAeadDemParams;
import com.google.crypto.tink.proto.EciesAeadHkdfKeyFormat;
import com.google.crypto.tink.proto.EciesAeadHkdfParams;
import com.google.crypto.tink.proto.EciesHkdfKemParams;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.proto.XChaCha20Poly1305KeyFormat;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
import org.junit.BeforeClass;
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

  private static final XChaCha20Poly1305KeyFormat DEM_KEY_FORMAT_PROTO =
      XChaCha20Poly1305KeyFormat.newBuilder().setVersion(0).build();

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  private static final class VariantTuple {
    final EciesParameters.Variant variant;
    final OutputPrefixType outputPrefixType;

    VariantTuple(
        EciesParameters.Variant variant,
        OutputPrefixType outputPrefixType,
        @Nullable Integer idRequirement) {
      this.variant = variant;
      this.outputPrefixType = outputPrefixType;
    }
  }

  @DataPoints("variants")
  public static final VariantTuple[] VARIANTS_TUPLES =
      new VariantTuple[] {
        new VariantTuple(
            EciesParameters.Variant.NO_PREFIX, OutputPrefixType.RAW, /* idRequirement= */ null),
        new VariantTuple(
            EciesParameters.Variant.TINK, OutputPrefixType.TINK, /* idRequirement= */ 123),
        new VariantTuple(
            EciesParameters.Variant.CRUNCHY, OutputPrefixType.CRUNCHY, /* idRequirement= */ 456),
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

  @BeforeClass
  public static void setUp() throws Exception {
    AeadConfig.register();
    EciesProtoSerialization.register(registry);
  }

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
            KeyTemplate.newBuilder()
                .setTypeUrl("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key")
                .setValue(DEM_KEY_FORMAT_PROTO.toByteString())
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());
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
            KeyTemplate.newBuilder()
                .setTypeUrl("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key")
                .setValue(DEM_KEY_FORMAT_PROTO.toByteString())
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());
    EciesAeadHkdfKeyFormat format =
        EciesAeadHkdfKeyFormat.newBuilder().setParams(protoParams).build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL, variantTuple.outputPrefixType, format);

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(EciesAeadHkdfKeyFormat.parser(), serialized, serialization);

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
            KeyTemplate.newBuilder()
                .setTypeUrl("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key")
                .setValue(DEM_KEY_FORMAT_PROTO.toByteString())
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());
    EciesAeadHkdfKeyFormat format =
        EciesAeadHkdfKeyFormat.newBuilder().setParams(protoParams).build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(PRIVATE_TYPE_URL, OutputPrefixType.RAW, format);

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(EciesAeadHkdfKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
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
                        KeyTemplate.newBuilder()
                            .setTypeUrl(
                                "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key")
                            .setValue(DEM_KEY_FORMAT_PROTO.toByteString())
                            .setOutputPrefixType(OutputPrefixType.RAW)
                            .build()))
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
                        KeyTemplate.newBuilder()
                            .setTypeUrl(
                                "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key")
                            .setValue(DEM_KEY_FORMAT_PROTO.toByteString())
                            .setOutputPrefixType(OutputPrefixType.RAW)
                            .build()))
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
                        KeyTemplate.newBuilder()
                            .setTypeUrl(
                                "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key")
                            .setValue(DEM_KEY_FORMAT_PROTO.toByteString())
                            .setOutputPrefixType(OutputPrefixType.RAW)
                            .build()))
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
                        KeyTemplate.newBuilder()
                            .setTypeUrl(
                                "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key")
                            .setValue(DEM_KEY_FORMAT_PROTO.toByteString())
                            .setOutputPrefixType(OutputPrefixType.RAW)
                            .build()))
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
                        KeyTemplate.newBuilder()
                            .setTypeUrl(
                                "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key")
                            .setValue(DEM_KEY_FORMAT_PROTO.toByteString())
                            .setOutputPrefixType(OutputPrefixType.RAW)
                            .build()))
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
                            .setValue(DEM_KEY_FORMAT_PROTO.toByteString())
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
        // Unknown dem key template prefix.
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
                            .setValue(DEM_KEY_FORMAT_PROTO.toByteString())
                            .setOutputPrefixType(OutputPrefixType.UNKNOWN_PREFIX)
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
}
