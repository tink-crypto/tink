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
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.proto.RsaSsaPkcs1Params;
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
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

    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.equalsKey(key)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, /* access= */ null);
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

    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.equalsKey(key)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, /* access= */ null);
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
  private static final String BINARY_HEX_KEYSET =
      "08e6fdc78e0612f1120ae4120a3c747970652e676f6f676c65617069732e636f6d2f676f6f676c652e6372797074"
          + "6f2e74696e6b2e527361537361506b637331507269766174654b657912a1124280021b0a2c139bb6920aac"
          + "82eaf97816144caf2c949e338e3997048db108a222c6ab542c37e05e1d882ee67bcbb332b7f7e68ef03841"
          + "a8e628c64e1c5b9fea1f99d6440df88a4ac4ceb84616c2a1a00473ec87e57afbe55dffab3b0f5b523170cd"
          + "d65666cb9fe6e039b937b27001f6c612f2bc8bd58b1ec59702a2c8661f722667f7a0171e9ce28a4f530d63"
          + "60174ca27e15f91ba4b9b166d9146044e651c3b09987f342a98130cdb753bcf811fa0fca6ebba8eb22cb63"
          + "80e4b2af73b0cf219613523da1a90a3cdb981b00c13e9ac84ca3bac19671507bf640da237e18dfeec46762"
          + "7fe279f50f4edb2460af5b3eb4488551179f1b79e52b73e2ce34a007965c74d13a800216b693a9b089b3a9"
          + "8dfae61a982a3132a262ca8f9895f0f88f0c68ea6b0b3128bec9c4c8baeb585a59cada1a244119ed205129"
          + "abd5d12fc1fa649cd9f4dfbec1763729db1ca07adb3e80e4e0e5e9859e1749f28ccecd09cc4d01c7bf88c5"
          + "1d675a9cc8e1ac8d3583427a741b6720b54dc0a838ca96fa1daf1f3b0f174907c4ff70b28fa4464c6ed1b8"
          + "4c31f0db396316d76b0e3dfc2630cdea0477cd42a1b5dcfcaa33c3e71e4ae5e3d0da86a423bd80b9722a09"
          + "93631926bbaecfd3f0c9effb952aaa1d92b924362af4459adb3a8addd648c4eb419190761301eeb5b5879f"
          + "8baa2a158dcd444323226c51d4b214af8f229fc343efbfb60a6efbfad3a028220132800297b0b9cbed3c4d"
          + "4986e01bae4ade0fb82d59a46f0c93a7847a5ccea29594bc4b6629aa29f93f7fb165e7ef6b6beedb6de90b"
          + "dfb250b3b5154535e33651f7afbf069193b773b53ec8b5d39862d1afc04c2cf84564dec9d2b3c6ee163f86"
          + "cd677289ecab1ba5156347120e19eaf7f2dd48825e4c9d594e6521e65871e791806a462bbe69fdb15abf9f"
          + "269bc717a332a0a67b7d9c0561513c93a06203b9a3c5ff3b22a4732ed2921d6c51ef9fd1c6bef8ac4ac6bc"
          + "0764b0651be580ed6a81f65d11c0e29c0f34f6b2be5b3484ab1da61f57b32a587ccf150936c1a11e5e256b"
          + "3d374842904e50ef80877f3ca2d72e6385779e167ed56fb08f70926ba8b51d946a672a8002ef02905ee0bc"
          + "448834cc0c105ee6e662783fab420faed753b0a02473e9dea19efda315f86caf13789b6cd743d65ef5919a"
          + "51a2286d0d37de37d82dfa7b0e1ff264a6650bf0b138e0a6e405fe244587a12aea3538737f72fbd725308e"
          + "bc9d702721e03f12cd7a3f7c22c34576056e2da528330783b09d603c6118c21c48f68c0d633a0dc368c38a"
          + "3343295c7251a4d7ba0f88892b02f77d4a9901e22596669e1e07337b125e77736df17ac0ad9244230a50af"
          + "15b14d4df4e511d21b681a38434f4c0dc81b7e0e6cd11b3ab87127849b8e44ffa36eeba5530440c800f8c6"
          + "821974a4a7b20f9240cc2eec696721dddb91028e57624f5fad5ef530c463f34c47c681228002fdcb088bcc"
          + "ca2bc29ec1b6db9ee965d139ec282f37fb0f503c226f6ce6cd28f20967a92e460e79c2e0bc91c32d49330a"
          + "52949b9c382a7096043e16ea258a26a468635a8e2b196b68e78a3183e7c88a4370e71bde39db3715acf908"
          + "ccfc10b17338ecd340fbb32bf0d8b26ae33fec0fd67c0c4e5eeb99e7f6ece62e19e3ba4092f4c84f49eb0c"
          + "dc92184ab2bd9bb8c9ed2a6f6d1a49abed648729ecf415257611fc16cebcd20e2e8fb5d5db9b518f8c1bcf"
          + "af01431e00bb0be100502c5518e31ee133684fa273740b339058fbf83e758ef75a99402e8b607b403fc933"
          + "b6ae6c12d4ec822a6c549408cee9c2a837a5bb41297b3152942bf04bd2c6b60b1cb508231a8004103ff9a3"
          + "74be0b78fc9c0be6a640552fdee22298bd1843ad7621b68e01e279d1533cf76f7711082518f07f3cd05257"
          + "c0505447be4e24c60227c8ff9b859f35413a31e83a889123f6e63f7997e8714677cd66597eab57c0424a47"
          + "a5c918700fde8e2d388fbffe7bc48c584ff6ef3e6ac22000ec193ab3436a90b55580abad0a9ec4d0b51221"
          + "7174348033ee5b88891aa31078e026d377b071992e97af149898d3a32ce23f50dcaf628b9461953e086cdc"
          + "3cdf1d09ef9b5c7020e113cefdc95978743c2b4a79396ea1720b0fb4432e9d266f989e68c4423c160cc08d"
          + "b706c31deb25967fa29f3ca38e396342cc654bf9b0be553be3b9e290ff9b53714bd720878c5ed82eea7583"
          + "397dc541f3060ef49170cef1a0b7b73f8d2f9d85871547690046d11614d1329a033e045724277c4cb45210"
          + "789e79d09c39230c8217a100a773c6fa11337d43b8f0522987b5432b340299d2b39d6f64b1c31a439819b7"
          + "03e90f8d7667e8137918d24debfaf4ca0d587e204d10b58d879571ce0aced5011e470ec2882b6c7f2ad0fa"
          + "0af7f747aebb6d122d21981d03a05ffa7680a31a5c5b0c435d2096b26076eb06b886b0b5a92491b29d3307"
          + "6a7abe0a83905cfb7bdb4247cf64cd6a3ea11c95740664e609653c0ea2055b10eb12dda0dd05a0f4c06ca6"
          + "171eb89c48c1986f92a66c76fab00be9c35e3bc3468e79a96d9dd824baed524b45c481128c042203010001"
          + "1a8004ecf317b0d9706b7b84ea20e79a19a802bcee8339a7251872b41cdc2f874686b20e33042771a1cd7c"
          + "33ec4d6c9f8cb85ae90d137c13e20c69b406afbf23281033758aa1f547b87d89efe6ede16a52d0045241b9"
          + "5f5e25dacef6000f88f82d5b4113e4ee0726c607f9dadae8bf1b8f38e768a9f851b957b1bab047e4c62b37"
          + "113819b724c1ea80c35d76b298ca06962706b2e73ae8158f462928e0ebe74bc3d1a62d32a1b770eb982d82"
          + "00ebac3fc64b81fe155ab59043ab54a142e146596326a29989e5e484b53bd3f3d6f9b97a989c5a9b45a1d0"
          + "05a393740b32bf870c1ca1c6f4d82b9483138dad2dd9ca9c3e1b1c8c760448d8ffc2a62866ed44823b3371"
          + "8c7126360b7b5aec2d40285ce1911d959d4a5c55d710165fea1c0b34a939261ecc3a625f31253d2fd2754e"
          + "a92b7e5b36ebc4f41445260f49dc88b447a1eaa3683f5c5b16a1f3d17aaf552e0a8f8b56c429e32ee0fea5"
          + "e6c54bcbbc547a24f6701f1f62c936d511ee78fcfd9b7206edb442188ea82ce452edd5c1ba76a8ca885c65"
          + "0bc48b649b0c835c6964d4d57bb8e9cd7d4eb749caf3263f5262d4ae0ab40071f7d4ddcbf5aeef83abffb8"
          + "8e64756659a004a30655732cd81e042a10197c0575334435e0d80805971203bae4ad61baadd47282638ef0"
          + "930f4b65add4cd5fbabdd794d2ddee3dc60253de50784f29c0a36160b3d39d66d6a8bd514aa621392ba312"
          + "0208041802100118e6fdc78e062003";

  @Test
  public void existingTinkKeyset_reencodesNumbersUsingTwoComplement() throws Exception {
    com.google.crypto.tink.proto.Keyset keyset =
        com.google.crypto.tink.proto.Keyset.parseFrom(
            Hex.decode(BINARY_HEX_KEYSET), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(keyset.getKeyCount()).isEqualTo(1);
    assertThat(keyset.getKey(0).getKeyData().getTypeUrl()).isEqualTo(PRIVATE_TYPE_URL);
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
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
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
