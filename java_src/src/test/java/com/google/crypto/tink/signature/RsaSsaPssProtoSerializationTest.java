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
import com.google.crypto.tink.JsonKeysetReader;
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
  private static final String JSON_KEYSET =
      ""
          + "{"
          + "  \"primaryKeyId\": 1747923325,"
          + "  \"key\": ["
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\":"
          + "\"type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey\","
          + "        \"value\": \"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"
          + "84iVi5NcSPU0SBhhAEAQIBA==\","
          + "        \"keyMaterialType\": \"ASYMMETRIC_PRIVATE\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 1747923325,"
          + "      \"outputPrefixType\": \"TINK\""
          + "    }"
          + "  ]"
          + "}";

  @Test
  public void existingTinkKeyset_reencodesNumbersUsingTwoComplement() throws Exception {
    com.google.crypto.tink.proto.Keyset keyset = JsonKeysetReader.withString(JSON_KEYSET).read();
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
