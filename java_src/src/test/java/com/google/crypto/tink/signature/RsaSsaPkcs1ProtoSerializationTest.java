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
import com.google.crypto.tink.proto.RsaSsaPkcs1Params;
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

/** Test for RsaSsaPkcs1ProtoSerialization. */
@RunWith(Theories.class)
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class RsaSsaPkcs1ProtoSerializationTest {

  private static final String PRIVATE_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey";
  private static final String PUBLIC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey";

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
    RsaSsaPkcs1ProtoSerialization.register(registry);
  }

  @Test
  public void serializeParseParameters_sha256_no_prefix_equal() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.RsaSsaPkcs1KeyFormat.newBuilder()
                .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(HashType.SHA256).build())
                .setModulusSizeInBits(2048)
                .setPublicExponent(ByteString.copyFrom(EXPONENT_BYTES))
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.RsaSsaPkcs1KeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_sha512_tink_equal() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA512)
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setVariant(RsaSsaPkcs1Parameters.Variant.TINK)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.TINK,
            com.google.crypto.tink.proto.RsaSsaPkcs1KeyFormat.newBuilder()
                .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(HashType.SHA512).build())
                .setModulusSizeInBits(2048)
                .setPublicExponent(ByteString.copyFrom(EXPONENT_BYTES))
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.RsaSsaPkcs1KeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_sha384_legacy_equal() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA384)
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setVariant(RsaSsaPkcs1Parameters.Variant.LEGACY)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.LEGACY,
            com.google.crypto.tink.proto.RsaSsaPkcs1KeyFormat.newBuilder()
                .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(HashType.SHA384).build())
                .setModulusSizeInBits(2048)
                .setPublicExponent(ByteString.copyFrom(EXPONENT_BYTES))
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.RsaSsaPkcs1KeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_sha256_crunchy_equal() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setVariant(RsaSsaPkcs1Parameters.Variant.CRUNCHY)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.CRUNCHY,
            com.google.crypto.tink.proto.RsaSsaPkcs1KeyFormat.newBuilder()
                .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(HashType.SHA256).build())
                .setModulusSizeInBits(2048)
                .setPublicExponent(ByteString.copyFrom(EXPONENT_BYTES))
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.RsaSsaPkcs1KeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializePublicParseKey_sha384_no_prefix_equal() throws Exception {
    RsaSsaPkcs1PublicKey key =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(
                RsaSsaPkcs1Parameters.builder()
                    .setHashType(RsaSsaPkcs1Parameters.HashType.SHA384)
                    .setModulusSizeBits(2048)
                    .setPublicExponent(EXPONENT)
                    .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                    .build())
            .setModulus(MODULUS)
            .build();
    com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey protoPublicKey =
        com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.newBuilder()
            .setVersion(0)
            .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(HashType.SHA384))
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
        com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.parser(), serialized, serialization);
  }

  @Test
  public void serializePublicParseKey_sha256_tink_equal() throws Exception {
    RsaSsaPkcs1PublicKey key =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(
                RsaSsaPkcs1Parameters.builder()
                    .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
                    .setModulusSizeBits(2048)
                    .setPublicExponent(EXPONENT)
                    .setVariant(RsaSsaPkcs1Parameters.Variant.TINK)
                    .build())
            .setModulus(MODULUS)
            .setIdRequirement(123)
            .build();
    com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey protoPublicKey =
        com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.newBuilder()
            .setVersion(0)
            .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(HashType.SHA256))
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
        com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.parser(), serialized, serialization);
  }

  @Test
  public void serializeParsePrivateKey_sha384_no_prefix_equal() throws Exception {
    RsaSsaPkcs1PublicKey publicKey =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(
                RsaSsaPkcs1Parameters.builder()
                    .setHashType(RsaSsaPkcs1Parameters.HashType.SHA384)
                    .setModulusSizeBits(2048)
                    .setPublicExponent(EXPONENT)
                    .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                    .build())
            .setModulus(MODULUS)
            .build();
    RsaSsaPkcs1PrivateKey privateKey =
        RsaSsaPkcs1PrivateKey.builder()
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

    com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey protoPrivateKey =
        com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(
                com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.newBuilder()
                    .setVersion(0)
                    .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(HashType.SHA384))
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

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(privateKey)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(
            privateKey, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());

    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey.parser(), serialized, serialization);
  }

  @Test
  public void serializeParsePrivateKey_sha512_tink_equal() throws Exception {
    RsaSsaPkcs1PublicKey publicKey =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(
                RsaSsaPkcs1Parameters.builder()
                    .setHashType(RsaSsaPkcs1Parameters.HashType.SHA512)
                    .setModulusSizeBits(2048)
                    .setPublicExponent(EXPONENT)
                    .setVariant(RsaSsaPkcs1Parameters.Variant.TINK)
                    .build())
            .setModulus(MODULUS)
            .setIdRequirement(123)
            .build();
    RsaSsaPkcs1PrivateKey privateKey =
        RsaSsaPkcs1PrivateKey.builder()
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

    com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey protoPrivateKey =
        com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(
                com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.newBuilder()
                    .setVersion(0)
                    .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(HashType.SHA512))
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
            OutputPrefixType.TINK,
            /* idRequirement= */ 123);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(privateKey)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(
            privateKey, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());

    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey.parser(), serialized, serialization);
  }

  // A keyset that contains a key generated in Python, which is based on C++. Big ints in C++
  // are encoded using the minimal encoding, and therefore may have the first bit set to 1.
  // In this key here, there are several such values, for example the factor "p". The test below
  // verifies that the value of "p" will get encoded differently.
  private static final String JSON_KEYSET =
      ""
          + "{"
          + "  \"primaryKeyId\": 1641152230,"
          + "  \"key\": ["
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\":"
          + "\"type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey\","
          + "        \"value\": \"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"
          + "ovVFKpiE5K6MSAggE\","
          + "        \"keyMaterialType\": \"ASYMMETRIC_PRIVATE\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 1641152230,"
          + "      \"outputPrefixType\": \"RAW\""
          + "    }"
          + "  ]"
          + "}";

  @Test
  public void existingTinkKeyset_reencodesNumbersUsingTwoComplement() throws Exception {
    com.google.crypto.tink.proto.Keyset keyset = JsonKeysetReader.withString(JSON_KEYSET).read();
    com.google.crypto.tink.proto.KeyData keyDataOfExistingKey = keyset.getKey(0).getKeyData();

    com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey existingKey =
        com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey.parseFrom(
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

    com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey serializedKey =
        com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey.parseFrom(
            serialized.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    byte[] encodedPInParsedKey = serializedKey.getP().toByteArray();

    // check that P is encoded differently.
    assertThat(encodedPInParsedKey).isNotEqualTo(encodedPInExistingKey);
    assertThat(encodedPInParsedKey).isEqualTo(ensureLeadingZeroBit(encodedPInExistingKey));
  }

  @Test
  public void parsePrivateKey_noAccess_fails() throws Exception {
    com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey protoPrivateKey =
        com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(
                com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.newBuilder()
                    .setVersion(0)
                    .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(HashType.SHA384))
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
    RsaSsaPkcs1PublicKey publicKey =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(
                RsaSsaPkcs1Parameters.builder()
                    .setHashType(RsaSsaPkcs1Parameters.HashType.SHA384)
                    .setModulusSizeBits(2048)
                    .setPublicExponent(EXPONENT)
                    .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                    .build())
            .setModulus(MODULUS)
            .build();
    RsaSsaPkcs1PrivateKey privateKey =
        RsaSsaPkcs1PrivateKey.builder()
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
            com.google.crypto.tink.proto.RsaSsaPkcs1KeyFormat.newBuilder()
                .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(HashType.SHA1).build())
                .setModulusSizeInBits(2048)
                .setPublicExponent(ByteString.copyFrom(EXPONENT_BYTES))
                .build()),
        // too small public exponent
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.RsaSsaPkcs1KeyFormat.newBuilder()
                .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(HashType.SHA256).build())
                .setModulusSizeInBits(2048)
                .setPublicExponent(ByteString.copyFrom(new byte[] {(byte) 0x03}))
                .build()),
        // too small modulus size in bits
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.RsaSsaPkcs1KeyFormat.newBuilder()
                .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(HashType.SHA256).build())
                .setModulusSizeInBits(123)
                .setPublicExponent(ByteString.copyFrom(EXPONENT_BYTES))
                .build()),
        // unknown output prefix
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.UNKNOWN_PREFIX,
            com.google.crypto.tink.proto.RsaSsaPkcs1KeyFormat.newBuilder()
                .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(HashType.SHA256).build())
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
            com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.newBuilder()
                .setVersion(0)
                .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(HashType.SHA256))
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
            com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.newBuilder()
                .setVersion(1)
                .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(HashType.SHA256))
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
            com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.newBuilder()
                .setVersion(0)
                .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(HashType.SHA256))
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
            com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.newBuilder()
                .setVersion(0)
                .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(HashType.SHA1))
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
            com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.newBuilder()
                .setVersion(0)
                .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(HashType.SHA256))
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
            com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(
                    com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.newBuilder()
                        .setVersion(0)
                        .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(HashType.SHA256))
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
            com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(
                    com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.newBuilder()
                        .setVersion(0)
                        .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(HashType.SHA256))
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
            com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey.newBuilder()
                .setVersion(1)
                .setPublicKey(
                    com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.newBuilder()
                        .setVersion(0)
                        .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(HashType.SHA256))
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
            com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(
                    com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.newBuilder()
                        .setVersion(0)
                        .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(HashType.SHA256))
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
            com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(
                    com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.newBuilder()
                        .setVersion(0)
                        .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(HashType.SHA1))
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
            com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(
                    com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.newBuilder()
                        .setVersion(0)
                        .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(HashType.SHA256))
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
