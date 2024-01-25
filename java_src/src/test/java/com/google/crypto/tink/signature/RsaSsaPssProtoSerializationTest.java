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

package com.google.crypto.tink.signature;

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
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.proto.RsaSsaPssParams;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Test for RsaSsaPssProtoSerialization. */
@RunWith(Theories.class)
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class RsaSsaPssProtoSerializationTest {

  private static final String PRIVATE_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey";
  private static final String PUBLIC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey";

  private static final byte[] ensureLeadingZeroBit(byte[] minimalEncodedBigInteger) {
    if (minimalEncodedBigInteger[0] < 0) {
      // add a leading zero to the encoding
      byte[] twosComplementEncoded = new byte[minimalEncodedBigInteger.length + 1];
      System.arraycopy(
          minimalEncodedBigInteger, 0, twosComplementEncoded, 1, minimalEncodedBigInteger.length);
      return twosComplementEncoded;
    }
    return minimalEncodedBigInteger;
  }

  @Test
  public void ensureLeadingZeroBit_works() throws Exception {
    // 258 = 1 * 256 + 2.
    // If the most significant bit is not set, there is no leading zero.
    byte[] encodingOf258 = new byte[] {(byte) 1, (byte) 2};
    assertThat(ensureLeadingZeroBit(encodingOf258)).isEqualTo(encodingOf258);

    // If the most significant bit is set, then a leading zero is added.
    byte[] encodingOf255 = new byte[] {(byte) 0xff};
    byte[] twoComplementEncodingOf255 = new byte[] {(byte) 0, (byte) 0xff};
    assertThat(ensureLeadingZeroBit(encodingOf255)).isEqualTo(twoComplementEncodingOf255);
  }

  // Test vector from https://www.rfc-editor.org/rfc/rfc7517#appendix-C.1
  //
  // Note that these test vectors use the minimal big-endian encoding of big integers. We however
  // use BigInteger.toByteArray() to encode big integers, which is the two-complement encoding.
  // This sometimes adds a leading zero to the encodings.
  // see: https://docs.oracle.com/javase/7/docs/api/java/math/BigInteger.html#toByteArray()
  static final byte[] EXPONENT_BYTES = ensureLeadingZeroBit(Base64.urlSafeDecode("AQAB"));
  static final BigInteger EXPONENT = new BigInteger(1, EXPONENT_BYTES);
  static final byte[] MODULUS_BYTES =
      ensureLeadingZeroBit(
          Base64.urlSafeDecode(
              "t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRy"
                  + "O125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP"
                  + "8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0"
                  + "Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0X"
                  + "OC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1"
                  + "_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q"));
  static final BigInteger MODULUS = new BigInteger(1, MODULUS_BYTES);
  static final byte[] P_BYTES =
      ensureLeadingZeroBit(
          Base64.urlSafeDecode(
              "2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHf"
                  + "QP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8"
                  + "UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws"));
  static final BigInteger P = new BigInteger(1, P_BYTES);
  static final byte[] Q_BYTES =
      ensureLeadingZeroBit(
          Base64.urlSafeDecode(
              "1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6I"
                  + "edis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYK"
                  + "rYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s"));
  static final BigInteger Q = new BigInteger(1, Q_BYTES);
  static final byte[] D_BYTES =
      ensureLeadingZeroBit(
          Base64.urlSafeDecode(
              "GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfS"
                  + "NkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9U"
                  + "vqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnu"
                  + "ToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqADC6p1M3h33tsu"
                  + "rY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWmeRDkK2a"
                  + "hecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ"));
  static final BigInteger D = new BigInteger(1, D_BYTES);
  static final byte[] DP_BYTES =
      ensureLeadingZeroBit(
          Base64.urlSafeDecode(
              "KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwKqvVDq3"
                  + "tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_lhqigI4y_kqS1w"
                  + "Y52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRViD6c"));
  static final BigInteger DP = new BigInteger(1, DP_BYTES);
  static final byte[] DQ_BYTES =
      ensureLeadingZeroBit(
          Base64.urlSafeDecode(
              "AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9"
                  + "GQTB9yqpDoYaN06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBy"
                  + "mXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEAu_lRFCOJ3xDea-ots"));
  static final BigInteger DQ = new BigInteger(1, DQ_BYTES);
  static final byte[] Q_INV_BYTES =
      ensureLeadingZeroBit(
          Base64.urlSafeDecode(
              "lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqq"
                  + "abu9V0-Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0o"
                  + "Yu_neotgQ0hzbI5gry7ajdYy9-2lNx_76aBZoOUu9HCJ-UsfSOI8"));
  static final BigInteger Q_INV = new BigInteger(1, Q_INV_BYTES);

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  @BeforeClass
  public static void setUp() throws Exception {
    RsaSsaPssProtoSerialization.register(registry);
  }

  @Test
  public void registerTwice() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    RsaSsaPssProtoSerialization.register(registry);
    RsaSsaPssProtoSerialization.register(registry);
  }

  @Test
  public void serializeParseParameters_sha256_no_prefix_equal() throws Exception {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.RsaSsaPssKeyFormat.newBuilder()
                .setParams(
                    RsaSsaPssParams.newBuilder()
                        .setSigHash(HashType.SHA256)
                        .setMgf1Hash(HashType.SHA256)
                        .setSaltLength(32)
                        .build())
                .setModulusSizeInBits(2048)
                .setPublicExponent(ByteString.copyFrom(EXPONENT_BYTES))
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.RsaSsaPssKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_sha384_tink_equal() throws Exception {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setSigHashType(RsaSsaPssParameters.HashType.SHA384)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA384)
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setVariant(RsaSsaPssParameters.Variant.TINK)
            .setSaltLengthBytes(48)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.TINK,
            com.google.crypto.tink.proto.RsaSsaPssKeyFormat.newBuilder()
                .setParams(
                    RsaSsaPssParams.newBuilder()
                        .setSigHash(HashType.SHA384)
                        .setMgf1Hash(HashType.SHA384)
                        .setSaltLength(48)
                        .build())
                .setModulusSizeInBits(2048)
                .setPublicExponent(ByteString.copyFrom(EXPONENT_BYTES))
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.RsaSsaPssKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_sha512_legacy_equal() throws Exception {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setSigHashType(RsaSsaPssParameters.HashType.SHA512)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA512)
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setVariant(RsaSsaPssParameters.Variant.LEGACY)
            .setSaltLengthBytes(64)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.LEGACY,
            com.google.crypto.tink.proto.RsaSsaPssKeyFormat.newBuilder()
                .setParams(
                    RsaSsaPssParams.newBuilder()
                        .setSigHash(HashType.SHA512)
                        .setMgf1Hash(HashType.SHA512)
                        .setSaltLength(64)
                        .build())
                .setModulusSizeInBits(2048)
                .setPublicExponent(ByteString.copyFrom(EXPONENT_BYTES))
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.RsaSsaPssKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_sha256_crunchy_equal() throws Exception {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setVariant(RsaSsaPssParameters.Variant.CRUNCHY)
            .setSaltLengthBytes(32)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.CRUNCHY,
            com.google.crypto.tink.proto.RsaSsaPssKeyFormat.newBuilder()
                .setParams(
                    RsaSsaPssParams.newBuilder()
                        .setSigHash(HashType.SHA256)
                        .setMgf1Hash(HashType.SHA256)
                        .setSaltLength(32)
                        .build())
                .setModulusSizeInBits(2048)
                .setPublicExponent(ByteString.copyFrom(EXPONENT_BYTES))
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.RsaSsaPssKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParsePublicKey_sha256_no_prefix_equal() throws Exception {
    RsaSsaPssPublicKey key =
        RsaSsaPssPublicKey.builder()
            .setParameters(
                RsaSsaPssParameters.builder()
                    .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
                    .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
                    .setModulusSizeBits(2048)
                    .setPublicExponent(EXPONENT)
                    .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                    .setSaltLengthBytes(32)
                    .build())
            .setModulus(MODULUS)
            .build();
    com.google.crypto.tink.proto.RsaSsaPssPublicKey protoPublicKey =
        com.google.crypto.tink.proto.RsaSsaPssPublicKey.newBuilder()
            .setVersion(0)
            .setParams(
                RsaSsaPssParams.newBuilder()
                    .setSigHash(HashType.SHA256)
                    .setMgf1Hash(HashType.SHA256)
                    .setSaltLength(32)
                    .build())
            .setN(ByteString.copyFrom(MODULUS_BYTES))
            .setE(ByteString.copyFrom(EXPONENT_BYTES))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.RsaSsaPssPublicKey.parser(), serialized, serialization);
  }

  @Test
  public void serializeParsePublicKey_sha384_tink_equal() throws Exception {
    RsaSsaPssPublicKey key =
        RsaSsaPssPublicKey.builder()
            .setParameters(
                RsaSsaPssParameters.builder()
                    .setSigHashType(RsaSsaPssParameters.HashType.SHA384)
                    .setMgf1HashType(RsaSsaPssParameters.HashType.SHA384)
                    .setModulusSizeBits(2048)
                    .setPublicExponent(EXPONENT)
                    .setVariant(RsaSsaPssParameters.Variant.TINK)
                    .setSaltLengthBytes(48)
                    .build())
            .setModulus(MODULUS)
            .setIdRequirement(123)
            .build();
    com.google.crypto.tink.proto.RsaSsaPssPublicKey protoPublicKey =
        com.google.crypto.tink.proto.RsaSsaPssPublicKey.newBuilder()
            .setVersion(0)
            .setParams(
                RsaSsaPssParams.newBuilder()
                    .setSigHash(HashType.SHA384)
                    .setMgf1Hash(HashType.SHA384)
                    .setSaltLength(48)
                    .build())
            .setN(ByteString.copyFrom(MODULUS_BYTES))
            .setE(ByteString.copyFrom(EXPONENT_BYTES))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 123);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.RsaSsaPssPublicKey.parser(), serialized, serialization);
  }

  @Test
  public void serializeParsePrivateKey_sha512_legacy_equal() throws Exception {
    RsaSsaPssPublicKey publicKey =
        RsaSsaPssPublicKey.builder()
            .setParameters(
                RsaSsaPssParameters.builder()
                    .setSigHashType(RsaSsaPssParameters.HashType.SHA512)
                    .setMgf1HashType(RsaSsaPssParameters.HashType.SHA512)
                    .setModulusSizeBits(2048)
                    .setPublicExponent(EXPONENT)
                    .setVariant(RsaSsaPssParameters.Variant.LEGACY)
                    .setSaltLengthBytes(64)
                    .build())
            .setModulus(MODULUS)
            .setIdRequirement(123)
            .build();
    RsaSsaPssPrivateKey privateKey =
        RsaSsaPssPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrimes(
                SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
            .setPrivateExponent(SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
            .setPrimeExponents(
                SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
            .setCrtCoefficient(
                SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
            .build();

    com.google.crypto.tink.proto.RsaSsaPssPrivateKey protoPrivateKey =
        com.google.crypto.tink.proto.RsaSsaPssPrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(
                com.google.crypto.tink.proto.RsaSsaPssPublicKey.newBuilder()
                    .setVersion(0)
                    .setParams(
                        RsaSsaPssParams.newBuilder()
                            .setSigHash(HashType.SHA512)
                            .setMgf1Hash(HashType.SHA512)
                            .setSaltLength(64)
                            .build())
                    .setN(ByteString.copyFrom(MODULUS_BYTES))
                    .setE(ByteString.copyFrom(EXPONENT_BYTES))
                    .build())
            .setD(ByteString.copyFrom(D_BYTES))
            .setP(ByteString.copyFrom(P_BYTES))
            .setQ(ByteString.copyFrom(Q_BYTES))
            .setDp(ByteString.copyFrom(DP_BYTES))
            .setDq(ByteString.copyFrom(DQ_BYTES))
            .setCrt(ByteString.copyFrom(Q_INV_BYTES))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            protoPrivateKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.LEGACY,
            /* idRequirement= */ 123);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(privateKey)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(
            privateKey, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());

    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.RsaSsaPssPrivateKey.parser(), serialized, serialization);
  }

  @Test
  public void serializeParsePrivateKey_sha512_crunchy_equal() throws Exception {
    RsaSsaPssPublicKey publicKey =
        RsaSsaPssPublicKey.builder()
            .setParameters(
                RsaSsaPssParameters.builder()
                    .setSigHashType(RsaSsaPssParameters.HashType.SHA512)
                    .setMgf1HashType(RsaSsaPssParameters.HashType.SHA512)
                    .setModulusSizeBits(2048)
                    .setPublicExponent(EXPONENT)
                    .setVariant(RsaSsaPssParameters.Variant.CRUNCHY)
                    .setSaltLengthBytes(64)
                    .build())
            .setModulus(MODULUS)
            .setIdRequirement(123)
            .build();
    RsaSsaPssPrivateKey privateKey =
        RsaSsaPssPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrimes(
                SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
            .setPrivateExponent(SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
            .setPrimeExponents(
                SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
            .setCrtCoefficient(
                SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
            .build();

    com.google.crypto.tink.proto.RsaSsaPssPrivateKey protoPrivateKey =
        com.google.crypto.tink.proto.RsaSsaPssPrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(
                com.google.crypto.tink.proto.RsaSsaPssPublicKey.newBuilder()
                    .setVersion(0)
                    .setParams(
                        RsaSsaPssParams.newBuilder()
                            .setSigHash(HashType.SHA512)
                            .setMgf1Hash(HashType.SHA512)
                            .setSaltLength(64)
                            .build())
                    .setN(ByteString.copyFrom(MODULUS_BYTES))
                    .setE(ByteString.copyFrom(EXPONENT_BYTES))
                    .build())
            .setD(ByteString.copyFrom(D_BYTES))
            .setP(ByteString.copyFrom(P_BYTES))
            .setQ(ByteString.copyFrom(Q_BYTES))
            .setDp(ByteString.copyFrom(DP_BYTES))
            .setDq(ByteString.copyFrom(DQ_BYTES))
            .setCrt(ByteString.copyFrom(Q_INV_BYTES))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            protoPrivateKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.CRUNCHY,
            /* idRequirement= */ 123);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(privateKey)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(
            privateKey, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());

    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.RsaSsaPssPrivateKey.parser(), serialized, serialization);
  }

  // A keyset that contains a key generated in Python, which is based on C++. Big ints in C++
  // are encoded using the minimal encoding, and therefore may have the first bit set to 1.
  // In this key here, there are several such values, for example the factor "p". The test below
  // verifies that the value of "p" will get encoded differently.
  private static final String BINARY_HEX_KEYSET =
      "08fde2bcc10612f3120ae6120a3a747970652e676f6f676c65617069732e636f6d2f676f6f676c652e6372797074"
          + "6f2e74696e6b2e527361537361507373507269766174654b657912a512428002867d190c7378d8f1b323a7"
          + "bfec519998dcffc67094b3c5d74ed2126745e3fad5ebbc353814fd33e79feb075caa9909d6b099d83f01a5"
          + "44f46ea5961b42ee9e92cca5c1170376f03a08fb56b48c54fa1435a450709e8eecd9154929d81faf4a01e3"
          + "b8caf7f191bffb55ab0fe785751524df650b69e6b2cfa72af873249cc4781357ef2ae4cc97600e27ec8a66"
          + "d8831680c53867941c09d2f07346cb5c45771ba7c4439928b6437d95996c0a4c30105af8689030354370a3"
          + "29d95aa8d4010e6b465cdfb0d8d7fd0f436871f9b2d88b11f0c90a6fd1f6ed68197ca5dcf14a35bffb3c2a"
          + "1ed9f2fc97645548dea7517184dd636e834b972c7df3c17c0761649bf2073a80026b96095a8d7118bb45d5"
          + "e569bfbdd8d70f44617608fd4bd9aa5f75086c0bf55590a4dc4310836065c4865971ffa0577e6e3ea0c10a"
          + "38119d6f30b8812ec2e08f5b5463cbe5ecf2ec6e95a20802c75f03ff4ad5df608ba1efac6971ee4268c66e"
          + "b97009441dca38ec41a6c6973974ff52cc55e917f0f3c7659acadc360cc5b23599a9690a84df80ca713ec5"
          + "e7095d2a818c3590f11f2586ff89f8a9dd41af34b3443919159438c115b2d3810d3b8c21c8e4ee75f63a44"
          + "54caac20da8dad1d1af033f7e98b239818dd363a3d77f1564278535b69eb25d54860aff9926facc70c76d0"
          + "ece90b05baac29a19d5d580c13fcd0534be27d3c8c6feab2097e9a064d6b753280025a23f264d0ece5d1b7"
          + "5f44ec652ed14b742c11cce4f63cc396671217f3d22fc586a583a1653db1426cdd29f579eca2f254e878e8"
          + "13537b65b6210e7bd0ed6c7b0a768ff9e0857e816da1bc6a416f613c7d2fe51e032832b71237b545864762"
          + "516289ee7b714cac397525feaf8ae5ae478434114a8f72c14dfb651f08e3590d6997f84497e5abd760fee4"
          + "548ed73caa54e4a79dd662c25824dddb2eb3981f8259a8f938de055f3d97845800d812281be2e8318c6e1f"
          + "4f9729f9fa514e0c8257a6693cf69260f64c30d87d7b895b2dcbf2175ad9c4e4f2833e5d9f01ec15ff3256"
          + "ab8097dc4f394a4a531438f40b8657d81cdcc029999637bcda265ba30d1632172a8002b5a86acc961611e3"
          + "bc34932862b83b20e99c6970786e3441a09536c82b4bb682575e19244b3b5a53be485a63488daab2b986df"
          + "604d33a4626939ffd3efd3fd6de4fba0c314e31a96d651061e4aca2049a5e5a01d7c2293bc65d7c193e34a"
          + "2de01a5fc24aff9b439eee2c239a52bc74149a2eb4bb02c14e0f9b3912469436b5c4d9a59b1d26dc75fe82"
          + "77d94f27b18312572279d9d35372ad6ab44b8b84fb92009ce5c5807a1602eb10ab1685a80635678752cb18"
          + "500f81ace02aad8199bc036974ad1a92e75dfd5ed32fa851e1f053e2dc1430d9b45d6f1f2c4566b3792027"
          + "aa30110e4fd9d609d0f22127d552ab40c1db7d062429e7f145e2e0118a7fdefb27228002c9fcd6092f4a46"
          + "a8ed2e4c218669d88b2fa37aed63935f5863bce2d5c88abfe1aa6788876f4078715a56231677d00188108c"
          + "dea5a080221cbda6644cc6c656ad369b51540ad030f0026894e8139f01372c90a7c28565e9140243ddd6c4"
          + "ef08788de5f141212199468903e4c625c573d6e1e9848d7d92e429bd97751fdb0b4e8bf027e23dba8d1731"
          + "b17f33fa1dbd0d9274a5bbf8b00c23bd90811839f845a03313a88551d113c8132231a3ddbfd7824346ca2e"
          + "dc61b2e84d3f2c5868aacaea0b944c14680458f0e0423a73f7b0dd7aa7c1295539df61896771328ff1c8cc"
          + "0dbdb87b33bf4129afbb368ffcd9eb7386997266a5a53f1063761a8cbf36afc11c6b1a80040d504005b1b3"
          + "b9e82d97d6f313c4e3100a24ff5ecb3ecb440a0cf45643a54be116d466bc26a9790502e9f9577f855b6eb2"
          + "4089c15049ea6ca30df1ec47e32c3a4699b30daf3c34493a7e738e3ef1a1c1dac7952ac87312d86c89b8f0"
          + "53bf967fc0d614f2ae7fded004a588331f5ae858fe857ad9b6d0433f4fa2f65e5d2f76baf153c1a1d30c33"
          + "45fc234507602e075361206cc34004f0056dc53d416e38627f22974416c8b2734cd705263fb0b532afdf90"
          + "ddb7bf1fd700b22b8a977c79e38fbe3babfda8cfc2cb80abb197cfdc6b3b4338ec4148c403793b397465fd"
          + "293eed00291c9bddc0686623103d7192dbd7c72fd75d1f3ffd945909e1bc70214bbd97a1a552155dea6fd2"
          + "6153523c8caba989693d33cd78dd8c4b4012b7cf9a95ba2d455c9f26d21cc48781469eb7345f471380bc24"
          + "7004f5c96714cf96f21832e4c6e45248a1269fd93a2a9e806c048d0323078c9f5c3893d661463bb8a987c1"
          + "313f249de385ba1aeb895a6d20828c51f6623dc2d1fbb8620d4385c97f048b82b1518ae317a191f48e0ca6"
          + "d66d275b2e84d74c2f4d17116173378b72e6ede146919e72f9ab837d155140f0b6e411800e63270260155e"
          + "37d0b27859feabb90cac1740f7c1704f2df2ad567f23d79206c4937cd0dad4c70a41a805cfd6ccbbd0780e"
          + "22b558b40107c667f13f16d0ae8e49f0c38481b2b967488e26aef823fef2d54c0312900422030100011a80"
          + "048f54a58510fc78db7f66c7c00663fef2116962ebfcc95f846b1c1641646d1106dd0da0c5b5ad03e9093a"
          + "e81208fe4b7cf2c8b89baef907317ef66e915eded8827c03afa6f16c7fa67586980d64dc230d09c0f5b0f7"
          + "2f0c92e89a7b6dc4682274c11a2b4e17475b5072483dc30bc153f49918221d0b756503ed56fcd6b4b237fd"
          + "7aad983c95e11ab0cf4ab7005dc10678ec29e169dc386ff626974f26d0736cb576cbf20a560d1417bb48c8"
          + "e1ddee9b439c88641ce2505e8efd211b6621276273d933c1908cdabec3e77dbacd27d0306e9e975402a675"
          + "b7adb0567226cbf80375700e549c4919ae0f94466b2fae23bae85436cb4513d22d10af0f0c2b383db00934"
          + "536d507b95de6b31801f7a4f6a759e20a27cec3237695f1d928ac1100c682d3123fff91e276837d4a5225c"
          + "0b5e0c90920149c09965e862dbe1a9dc2c1edbd85f88c58831ee34a11a3af146f62ebf64f8361a7e2a89a4"
          + "697c5b3ebf18c9eb059339d3be7dff502d1a1a03dd0bf7d50be49991b922babfe24c6e3def41a9356c3c9d"
          + "3690a0dd99191c65bc6def5284302edd2f777cc592365bc2ca03dcf1ebc8c5dc628bd654ae37dfa1a7ab82"
          + "f198b0c722dfc4edef2bb8137b58697eec914752cb4e55ff89661b1b25e341e9b6299a80f731ec172669b0"
          + "af07d4c6bd933fc319b45ee57bfe0d42dc7908d1995adaadad5c0efeb68928fce22562e4d7123d4d120618"
          + "40100408041802100118fde2bcc1062001";

  @Test
  public void existingTinkKeyset_reencodesNumbersUsingTwoComplement() throws Exception {
    com.google.crypto.tink.proto.Keyset keyset =
        com.google.crypto.tink.proto.Keyset.parseFrom(
            Hex.decode(BINARY_HEX_KEYSET), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(keyset.getKeyCount()).isEqualTo(1);
    assertThat(keyset.getKey(0).getKeyData().getTypeUrl()).isEqualTo(PRIVATE_TYPE_URL);
    com.google.crypto.tink.proto.KeyData keyDataOfExistingKey = keyset.getKey(0).getKeyData();

    com.google.crypto.tink.proto.RsaSsaPssPrivateKey existingKey =
        com.google.crypto.tink.proto.RsaSsaPssPrivateKey.parseFrom(
            keyDataOfExistingKey.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    byte[] encodedPInExistingKey = existingKey.getP().toByteArray();

    ProtoKeySerialization serializationOfExistingKey =
        ProtoKeySerialization.create(
            keyDataOfExistingKey.getTypeUrl(),
            keyDataOfExistingKey.getValue(),
            keyDataOfExistingKey.getKeyMaterialType(),
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    Key parsed = registry.parseKey(serializationOfExistingKey, InsecureSecretKeyAccess.get());
    ProtoKeySerialization serialized =
        registry.serializeKey(parsed, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());

    com.google.crypto.tink.proto.RsaSsaPssPrivateKey serializedKey =
        com.google.crypto.tink.proto.RsaSsaPssPrivateKey.parseFrom(
            serialized.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    byte[] encodedPInParsedKey = serializedKey.getP().toByteArray();

    // check that P is encoded differently.
    assertThat(encodedPInParsedKey).isNotEqualTo(encodedPInExistingKey);
    assertThat(encodedPInParsedKey).isEqualTo(ensureLeadingZeroBit(encodedPInExistingKey));
  }

  @Test
  public void parsePrivateKey_noAccess_fails() throws Exception {
    com.google.crypto.tink.proto.RsaSsaPssPrivateKey protoPrivateKey =
        com.google.crypto.tink.proto.RsaSsaPssPrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(
                com.google.crypto.tink.proto.RsaSsaPssPublicKey.newBuilder()
                    .setVersion(0)
                    .setParams(
                        RsaSsaPssParams.newBuilder()
                            .setSigHash(HashType.SHA512)
                            .setMgf1Hash(HashType.SHA512)
                            .setSaltLength(64)
                            .build())
                    .setN(ByteString.copyFrom(MODULUS_BYTES))
                    .setE(ByteString.copyFrom(EXPONENT_BYTES))
                    .build())
            .setD(ByteString.copyFrom(D_BYTES))
            .setP(ByteString.copyFrom(P_BYTES))
            .setQ(ByteString.copyFrom(Q_BYTES))
            .setDp(ByteString.copyFrom(DP_BYTES))
            .setDq(ByteString.copyFrom(DQ_BYTES))
            .setCrt(ByteString.copyFrom(Q_INV_BYTES))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            protoPrivateKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
  }

  @Test
  public void serializePrivateKey_noAccess_throws() throws Exception {
    RsaSsaPssPublicKey publicKey =
        RsaSsaPssPublicKey.builder()
            .setParameters(
                RsaSsaPssParameters.builder()
                    .setSigHashType(RsaSsaPssParameters.HashType.SHA512)
                    .setMgf1HashType(RsaSsaPssParameters.HashType.SHA512)
                    .setModulusSizeBits(2048)
                    .setPublicExponent(EXPONENT)
                    .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                    .setSaltLengthBytes(64)
                    .build())
            .setModulus(MODULUS)
            .build();
    RsaSsaPssPrivateKey privateKey =
        RsaSsaPssPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrimes(
                SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
            .setPrivateExponent(SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
            .setPrimeExponents(
                SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
            .setCrtCoefficient(
                SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
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
            com.google.crypto.tink.proto.RsaSsaPssKeyFormat.newBuilder()
                .setParams(
                    RsaSsaPssParams.newBuilder()
                        .setSigHash(HashType.SHA1)
                        .setMgf1Hash(HashType.SHA1)
                        .setSaltLength(2)
                        .build())
                .setModulusSizeInBits(2048)
                .setPublicExponent(ByteString.copyFrom(EXPONENT_BYTES))
                .build()),
        // different hash types for signature and mgf1
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.RsaSsaPssKeyFormat.newBuilder()
                .setParams(
                    RsaSsaPssParams.newBuilder()
                        .setSigHash(HashType.SHA256)
                        .setMgf1Hash(HashType.SHA512)
                        .setSaltLength(32)
                        .build())
                .setModulusSizeInBits(2048)
                .setPublicExponent(ByteString.copyFrom(EXPONENT_BYTES))
                .build()),
        // too small public exponent
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.RsaSsaPssKeyFormat.newBuilder()
                .setParams(
                    RsaSsaPssParams.newBuilder()
                        .setSigHash(HashType.SHA256)
                        .setMgf1Hash(HashType.SHA256)
                        .setSaltLength(32)
                        .build())
                .setModulusSizeInBits(2048)
                .setPublicExponent(ByteString.copyFrom(new byte[] {(byte) 0x03}))
                .build()),
        // negative salt length
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.RsaSsaPssKeyFormat.newBuilder()
                .setParams(
                    RsaSsaPssParams.newBuilder()
                        .setSigHash(HashType.SHA256)
                        .setMgf1Hash(HashType.SHA256)
                        .setSaltLength(-32)
                        .build())
                .setModulusSizeInBits(2048)
                .setPublicExponent(ByteString.copyFrom(new byte[] {(byte) 0x03}))
                .build()),
        // too small modulus size in bits
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.RsaSsaPssKeyFormat.newBuilder()
                .setParams(
                    RsaSsaPssParams.newBuilder()
                        .setSigHash(HashType.SHA256)
                        .setMgf1Hash(HashType.SHA256)
                        .setSaltLength(32)
                        .build())
                .setModulusSizeInBits(123)
                .setPublicExponent(ByteString.copyFrom(EXPONENT_BYTES))
                .build()),
        // unknown output prefix
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.UNKNOWN_PREFIX,
            com.google.crypto.tink.proto.RsaSsaPssKeyFormat.newBuilder()
                .setParams(
                    RsaSsaPssParams.newBuilder()
                        .setSigHash(HashType.SHA256)
                        .setMgf1Hash(HashType.SHA256)
                        .setSaltLength(32)
                        .build())
                .setModulusSizeInBits(2048)
                .setPublicExponent(ByteString.copyFrom(EXPONENT_BYTES))
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
      return new ProtoKeySerialization[] {
        // Public exponent too small
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            com.google.crypto.tink.proto.RsaSsaPssPublicKey.newBuilder()
                .setVersion(0)
                .setParams(
                    RsaSsaPssParams.newBuilder()
                        .setSigHash(HashType.SHA256)
                        .setMgf1Hash(HashType.SHA256)
                        .setSaltLength(32)
                        .build())
                .setN(ByteString.copyFrom(MODULUS_BYTES))
                .setE(ByteString.copyFrom(new byte[] {(byte) 0x03}))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            1479),
        // Bad Version Number (1)
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            com.google.crypto.tink.proto.RsaSsaPssPublicKey.newBuilder()
                .setVersion(1)
                .setParams(
                    RsaSsaPssParams.newBuilder()
                        .setSigHash(HashType.SHA256)
                        .setMgf1Hash(HashType.SHA256)
                        .setSaltLength(32)
                        .build())
                .setN(ByteString.copyFrom(MODULUS_BYTES))
                .setE(ByteString.copyFrom(EXPONENT_BYTES))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            1479),
        // Unknown prefix
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            com.google.crypto.tink.proto.RsaSsaPssPublicKey.newBuilder()
                .setVersion(0)
                .setParams(
                    RsaSsaPssParams.newBuilder()
                        .setSigHash(HashType.SHA256)
                        .setMgf1Hash(HashType.SHA256)
                        .setSaltLength(32)
                        .build())
                .setN(ByteString.copyFrom(MODULUS_BYTES))
                .setE(ByteString.copyFrom(EXPONENT_BYTES))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.UNKNOWN_PREFIX,
            1479),
        // Bad Hash type
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            com.google.crypto.tink.proto.RsaSsaPssPublicKey.newBuilder()
                .setVersion(0)
                .setParams(
                    RsaSsaPssParams.newBuilder()
                        .setSigHash(HashType.SHA1)
                        .setMgf1Hash(HashType.SHA1)
                        .setSaltLength(2)
                        .build())
                .setN(ByteString.copyFrom(MODULUS_BYTES))
                .setE(ByteString.copyFrom(EXPONENT_BYTES))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            1479),
        // Different hash types for signature and mgf1
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            com.google.crypto.tink.proto.RsaSsaPssPublicKey.newBuilder()
                .setVersion(0)
                .setParams(
                    RsaSsaPssParams.newBuilder()
                        .setSigHash(HashType.SHA256)
                        .setMgf1Hash(HashType.SHA384)
                        .setSaltLength(32)
                        .build())
                .setN(ByteString.copyFrom(MODULUS_BYTES))
                .setE(ByteString.copyFrom(EXPONENT_BYTES))
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
            com.google.crypto.tink.proto.RsaSsaPssPublicKey.newBuilder()
                .setVersion(0)
                .setParams(
                    RsaSsaPssParams.newBuilder()
                        .setSigHash(HashType.SHA256)
                        .setMgf1Hash(HashType.SHA256)
                        .setSaltLength(32)
                        .build())
                .setN(ByteString.copyFrom(MODULUS_BYTES))
                .setE(ByteString.copyFrom(EXPONENT_BYTES))
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
      return new ProtoKeySerialization[] {
        // Missing value in private key
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            com.google.crypto.tink.proto.RsaSsaPssPrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(
                    com.google.crypto.tink.proto.RsaSsaPssPublicKey.newBuilder()
                        .setVersion(0)
                        .setParams(
                            RsaSsaPssParams.newBuilder()
                                .setSigHash(HashType.SHA512)
                                .setMgf1Hash(HashType.SHA512)
                                .setSaltLength(64)
                                .build())
                        .setN(ByteString.copyFrom(MODULUS_BYTES))
                        .setE(ByteString.copyFrom(EXPONENT_BYTES))
                        .build())
                .setD(ByteString.copyFrom(D_BYTES))
                .setP(ByteString.copyFrom(P_BYTES))
                .setQ(ByteString.copyFrom(Q_BYTES))
                .setDp(ByteString.copyFrom(DP_BYTES))
                .setDq(ByteString.copyFrom(DQ_BYTES))
                // missing Q_INV
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            1479),
        // Invalid private values
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            com.google.crypto.tink.proto.RsaSsaPssPrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(
                    com.google.crypto.tink.proto.RsaSsaPssPublicKey.newBuilder()
                        .setVersion(0)
                        .setParams(
                            RsaSsaPssParams.newBuilder()
                                .setSigHash(HashType.SHA512)
                                .setMgf1Hash(HashType.SHA512)
                                .setSaltLength(64)
                                .build())
                        .setN(ByteString.copyFrom(MODULUS_BYTES))
                        .setE(ByteString.copyFrom(EXPONENT_BYTES))
                        .build())
                .setD(ByteString.copyFrom(D_BYTES))
                .setP(ByteString.copyFrom(P_BYTES))
                .setQ(ByteString.copyFrom(Q_BYTES))
                // DQ_BYTES and DP_BYTES are switched
                .setDp(ByteString.copyFrom(DQ_BYTES))
                .setDq(ByteString.copyFrom(DP_BYTES))
                .setCrt(ByteString.copyFrom(Q_INV_BYTES))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            1479),
        // Bad Version Number (1)
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            com.google.crypto.tink.proto.RsaSsaPssPrivateKey.newBuilder()
                .setVersion(1)
                .setPublicKey(
                    com.google.crypto.tink.proto.RsaSsaPssPublicKey.newBuilder()
                        .setVersion(0)
                        .setParams(
                            RsaSsaPssParams.newBuilder()
                                .setSigHash(HashType.SHA512)
                                .setMgf1Hash(HashType.SHA512)
                                .setSaltLength(64)
                                .build())
                        .setN(ByteString.copyFrom(MODULUS_BYTES))
                        .setE(ByteString.copyFrom(EXPONENT_BYTES))
                        .build())
                .setD(ByteString.copyFrom(D_BYTES))
                .setP(ByteString.copyFrom(P_BYTES))
                .setQ(ByteString.copyFrom(Q_BYTES))
                .setDp(ByteString.copyFrom(DP_BYTES))
                .setDq(ByteString.copyFrom(DQ_BYTES))
                .setCrt(ByteString.copyFrom(Q_INV_BYTES))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            1479),
        // Unknown prefix
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            com.google.crypto.tink.proto.RsaSsaPssPrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(
                    com.google.crypto.tink.proto.RsaSsaPssPublicKey.newBuilder()
                        .setVersion(0)
                        .setParams(
                            RsaSsaPssParams.newBuilder()
                                .setSigHash(HashType.SHA512)
                                .setMgf1Hash(HashType.SHA512)
                                .setSaltLength(64)
                                .build())
                        .setN(ByteString.copyFrom(MODULUS_BYTES))
                        .setE(ByteString.copyFrom(EXPONENT_BYTES))
                        .build())
                .setD(ByteString.copyFrom(D_BYTES))
                .setP(ByteString.copyFrom(P_BYTES))
                .setQ(ByteString.copyFrom(Q_BYTES))
                .setDp(ByteString.copyFrom(DP_BYTES))
                .setDq(ByteString.copyFrom(DQ_BYTES))
                .setCrt(ByteString.copyFrom(Q_INV_BYTES))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.UNKNOWN_PREFIX,
            1479),
        // Bad Public key (invalid hash function)
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            com.google.crypto.tink.proto.RsaSsaPssPrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(
                    com.google.crypto.tink.proto.RsaSsaPssPublicKey.newBuilder()
                        .setVersion(0)
                        .setParams(
                            RsaSsaPssParams.newBuilder()
                                .setSigHash(HashType.SHA1)
                                .setMgf1Hash(HashType.SHA1)
                                .setSaltLength(2)
                                .build())
                        .setN(ByteString.copyFrom(MODULUS_BYTES))
                        .setE(ByteString.copyFrom(EXPONENT_BYTES))
                        .build())
                .setD(ByteString.copyFrom(D_BYTES))
                .setP(ByteString.copyFrom(P_BYTES))
                .setQ(ByteString.copyFrom(Q_BYTES))
                .setDp(ByteString.copyFrom(DP_BYTES))
                .setDq(ByteString.copyFrom(DQ_BYTES))
                .setCrt(ByteString.copyFrom(Q_INV_BYTES))
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
            com.google.crypto.tink.proto.RsaSsaPssPrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(
                    com.google.crypto.tink.proto.RsaSsaPssPublicKey.newBuilder()
                        .setVersion(0)
                        .setParams(
                            RsaSsaPssParams.newBuilder()
                                .setSigHash(HashType.SHA256)
                                .setMgf1Hash(HashType.SHA256)
                                .setSaltLength(32)
                                .build())
                        .setN(ByteString.copyFrom(MODULUS_BYTES))
                        .setE(ByteString.copyFrom(EXPONENT_BYTES))
                        .build())
                .setD(ByteString.copyFrom(D_BYTES))
                .setP(ByteString.copyFrom(P_BYTES))
                .setQ(ByteString.copyFrom(Q_BYTES))
                .setDp(ByteString.copyFrom(DP_BYTES))
                .setDq(ByteString.copyFrom(DQ_BYTES))
                .setCrt(ByteString.copyFrom(Q_INV_BYTES))
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
