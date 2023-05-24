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
import static com.google.crypto.tink.internal.testing.Asserts.assertEqualWhenValueParsed;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.HpkeAead;
import com.google.crypto.tink.proto.HpkeKdf;
import com.google.crypto.tink.proto.HpkeKem;
import com.google.crypto.tink.proto.HpkeKeyFormat;
import com.google.crypto.tink.proto.HpkeParams;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
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

/** Unit tests for {@link HpkeProtoSerialization}. */
@RunWith(Theories.class)
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class HpkeProtoSerializationTest {
  private static final class VariantTuple {
    final HpkeParameters.Variant variant;
    final OutputPrefixType outputPrefixType;
    @Nullable final Integer idRequirement;

    VariantTuple(
        HpkeParameters.Variant variant,
        OutputPrefixType outputPrefixType,
        @Nullable Integer idRequirement) {
      this.variant = variant;
      this.outputPrefixType = outputPrefixType;
      this.idRequirement = idRequirement;
    }
  }

  private static final class KemTuple {
    final HpkeParameters.KemId kemId;
    final HpkeKem kemProto;
    final byte[] publicKey;

    KemTuple(HpkeParameters.KemId kemId, HpkeKem kemProto, byte[] publicKey) {
      this.kemId = kemId;
      this.kemProto = kemProto;
      this.publicKey = publicKey;
    }
  }

  private static final class KdfTuple {
    final HpkeParameters.KdfId kdfId;
    final HpkeKdf kdfProto;

    KdfTuple(HpkeParameters.KdfId kdfId, HpkeKdf kdfProto) {
      this.kdfId = kdfId;
      this.kdfProto = kdfProto;
    }
  }

  private static final class AeadTuple {
    final HpkeParameters.AeadId aeadId;
    final HpkeAead aeadProto;

    AeadTuple(HpkeParameters.AeadId aeadId, HpkeAead aeadProto) {
      this.aeadId = aeadId;
      this.aeadProto = aeadProto;
    }
  }

  private static final String PUBLIC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.HpkePublicKey";
  private static final String PRIVATE_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.HpkePrivateKey";

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  @DataPoints("variants")
  public static final VariantTuple[] VARIANTS =
      new VariantTuple[] {
        new VariantTuple(
            HpkeParameters.Variant.NO_PREFIX, OutputPrefixType.RAW, /* idRequirement= */ null),
        new VariantTuple(
            HpkeParameters.Variant.TINK, OutputPrefixType.TINK, /* idRequirement= */ 123),
        new VariantTuple(
            HpkeParameters.Variant.CRUNCHY, OutputPrefixType.CRUNCHY, /* idRequirement= */ 456),
      };

  @DataPoints("kems")
  public static final KemTuple[] KEMS =
      new KemTuple[] {
        new KemTuple(
            // Ephemeral key pair from https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1.1.
            HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256,
            HpkeKem.DHKEM_X25519_HKDF_SHA256,
            /* publicKey= */ Hex.decode(
                "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")),
        new KemTuple(
            // Ephemeral key pair from https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.3.1.
            HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256,
            HpkeKem.DHKEM_P256_HKDF_SHA256,
            /* publicKey= */ Hex.decode(
                "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b32"
                    + "5ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4")),
        new KemTuple(
            // Ephemeral key pair from  https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.6.1.
            HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512,
            HpkeKem.DHKEM_P521_HKDF_SHA512,
            /* publicKey= */ Hex.decode(
                "040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8"
                    + "900aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731"
                    + "ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed0"
                    + "692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0")),
      };

  @DataPoints("kdfs")
  public static final KdfTuple[] KDFS =
      new KdfTuple[] {
        new KdfTuple(HpkeParameters.KdfId.HKDF_SHA256, HpkeKdf.HKDF_SHA256),
        new KdfTuple(HpkeParameters.KdfId.HKDF_SHA384, HpkeKdf.HKDF_SHA384),
        new KdfTuple(HpkeParameters.KdfId.HKDF_SHA512, HpkeKdf.HKDF_SHA512),
      };

  @DataPoints("aeads")
  public static final AeadTuple[] AEADS =
      new AeadTuple[] {
        new AeadTuple(HpkeParameters.AeadId.AES_128_GCM, HpkeAead.AES_128_GCM),
        new AeadTuple(HpkeParameters.AeadId.AES_256_GCM, HpkeAead.AES_256_GCM),
        new AeadTuple(HpkeParameters.AeadId.CHACHA20_POLY1305, HpkeAead.CHACHA20_POLY1305),
      };

  private static final HpkeParams createHpkeProtoParams(HpkeKem kem, HpkeKdf kdf, HpkeAead aead) {
    return HpkeParams.newBuilder().setKem(kem).setKdf(kdf).setAead(aead).build();
  }

  private static final com.google.crypto.tink.proto.HpkePublicKey createHpkeProtoPublicKey(
      int version, HpkeParams params, byte[] publicKey) {
    return com.google.crypto.tink.proto.HpkePublicKey.newBuilder()
        .setVersion(version)
        .setParams(params)
        .setPublicKey(ByteString.copyFrom(publicKey))
        .build();
  }

  @BeforeClass
  public static void setUp() throws Exception {
    HpkeProtoSerialization.register(registry);
  }

  @Test
  public void register_calledTwice_succeedsAndSecondCallHasNoEffect() throws Exception {
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .build();

    HpkeParams protoParams =
        createHpkeProtoParams(
            HpkeKem.DHKEM_X25519_HKDF_SHA256, HpkeKdf.HKDF_SHA256, HpkeAead.AES_128_GCM);
    HpkeKeyFormat format = HpkeKeyFormat.newBuilder().setParams(protoParams).build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.HpkePrivateKey", OutputPrefixType.RAW, format);

    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    assertThat(registry.hasParserForParameters(serialization)).isFalse();
    assertThat(registry.hasSerializerForParameters(parameters, ProtoParametersSerialization.class))
        .isFalse();

    HpkeProtoSerialization.register(registry);

    assertThat(registry.hasParserForParameters(serialization)).isTrue();
    assertThat(registry.hasSerializerForParameters(parameters, ProtoParametersSerialization.class))
        .isTrue();

    HpkeProtoSerialization.register(registry);

    assertThat(registry.hasParserForParameters(serialization)).isTrue();
    assertThat(registry.hasSerializerForParameters(parameters, ProtoParametersSerialization.class))
        .isTrue();
  }

  @Theory
  public void serializeParseParameters(
      @FromDataPoints("variants") VariantTuple variantTuple,
      @FromDataPoints("kems") KemTuple kemTuple,
      @FromDataPoints("kdfs") KdfTuple kdfTuple,
      @FromDataPoints("aeads") AeadTuple aeadTuple)
      throws Exception {
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setKemId(kemTuple.kemId)
            .setKdfId(kdfTuple.kdfId)
            .setAeadId(aeadTuple.aeadId)
            .setVariant(variantTuple.variant)
            .build();

    HpkeParams protoParams =
        createHpkeProtoParams(kemTuple.kemProto, kdfTuple.kdfProto, aeadTuple.aeadProto);
    HpkeKeyFormat format = HpkeKeyFormat.newBuilder().setParams(protoParams).build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.HpkePrivateKey",
            variantTuple.outputPrefixType,
            format);

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(HpkeKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Theory
  public void serializeParsePublicKey(
      @FromDataPoints("variants") VariantTuple variantTuple,
      @FromDataPoints("kems") KemTuple kemTuple,
      @FromDataPoints("kdfs") KdfTuple kdfTuple,
      @FromDataPoints("aeads") AeadTuple aeadTuple)
      throws Exception {
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setKemId(kemTuple.kemId)
            .setKdfId(kdfTuple.kdfId)
            .setAeadId(aeadTuple.aeadId)
            .setVariant(variantTuple.variant)
            .build();
    HpkePublicKey publicKey =
        HpkePublicKey.create(
            parameters, Bytes.copyFrom(kemTuple.publicKey), variantTuple.idRequirement);

    HpkeParams protoParams =
        createHpkeProtoParams(kemTuple.kemProto, kdfTuple.kdfProto, aeadTuple.aeadProto);
    com.google.crypto.tink.proto.HpkePublicKey protoPublicKey =
        createHpkeProtoPublicKey(/* version= */ 0, protoParams, kemTuple.publicKey);

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.HpkePublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            variantTuple.outputPrefixType,
            variantTuple.idRequirement);

    Key parsed = registry.parseKey(serialization, /* access = */ null);
    assertThat(parsed.equalsKey(publicKey)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(
            publicKey, ProtoKeySerialization.class, /* access = */ null);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.HpkePublicKey.parser(), serialized, serialization);
  }

  @DataPoints("invalidParametersSerializations")
  public static final ProtoParametersSerialization[] INVALID_PARAMETERS_SERIALIZATIONS =
      new ProtoParametersSerialization[] {
        // Unknown output prefix.
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.UNKNOWN_PREFIX,
            HpkeKeyFormat.newBuilder()
                .setParams(
                    createHpkeProtoParams(KEMS[0].kemProto, KDFS[0].kdfProto, AEADS[0].aeadProto))
                .build()),
        // Unknown KEM.
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.TINK,
            HpkeKeyFormat.newBuilder()
                .setParams(
                    createHpkeProtoParams(
                        HpkeKem.KEM_UNKNOWN, KDFS[0].kdfProto, AEADS[0].aeadProto))
                .build()),
        // Unknown KDF.
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.TINK,
            HpkeKeyFormat.newBuilder()
                .setParams(
                    createHpkeProtoParams(
                        KEMS[0].kemProto, HpkeKdf.KDF_UNKNOWN, AEADS[0].aeadProto))
                .build()),
        // Unknown AEAD.
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.TINK,
            HpkeKeyFormat.newBuilder()
                .setParams(
                    createHpkeProtoParams(
                        KEMS[0].kemProto, KDFS[0].kdfProto, HpkeAead.AEAD_UNKNOWN))
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

  private static ProtoKeySerialization[] createInvalidPublicKeySerializations() {
    try {
      return new ProtoKeySerialization[] {
        // Bad Version Number (1)
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            createHpkeProtoPublicKey(
                    /* version= */ 1,
                    createHpkeProtoParams(KEMS[0].kemProto, KDFS[0].kdfProto, AEADS[0].aeadProto),
                    KEMS[0].publicKey)
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            123),
        // Unknown prefix
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            createHpkeProtoPublicKey(
                    /* version= */ 0,
                    createHpkeProtoParams(KEMS[0].kemProto, KDFS[0].kdfProto, AEADS[0].aeadProto),
                    KEMS[0].publicKey)
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.UNKNOWN_PREFIX,
            123),
        // Invalid proto encoding
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            // Proto messages start with a VarInt, which always ends with a byte with most
            // significant bit unset. 0x80 is hence invalid.
            ByteString.copyFrom(new byte[] {(byte) 0x80}),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            123),
        // Wrong Type URL
        ProtoKeySerialization.create(
            "WrongTypeUrl",
            createHpkeProtoPublicKey(
                    /* version= */ 0,
                    createHpkeProtoParams(KEMS[0].kemProto, KDFS[0].kdfProto, AEADS[0].aeadProto),
                    KEMS[0].publicKey)
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            123),
      };
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  @DataPoints("invalidPublicKeySerializations")
  public static final ProtoKeySerialization[] INVALID_PUBLIC_KEY_SERIALIZATIONS =
      createInvalidPublicKeySerializations();

  @Theory
  public void parseInvalidPublicKeys_throws(
      @FromDataPoints("invalidPublicKeySerializations") ProtoKeySerialization serialization) {
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(serialization, /* access = */ null));
  }
}
