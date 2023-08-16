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
import com.google.crypto.tink.internal.testing.BigIntegerTestUtil;
import com.google.crypto.tink.proto.JwtRsaSsaPkcs1Algorithm;
import com.google.crypto.tink.proto.JwtRsaSsaPkcs1KeyFormat;
import com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey.CustomKid;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.protobuf.ByteString;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public final class JwtRsaSsaPkcs1ProtoSerializationTest {
  private static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey";

  // Test vector from https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2
  static final byte[] EXPONENT_BYTES =
      BigIntegerTestUtil.ensureLeadingZeroBit(Base64.urlSafeDecode("AQAB"));
  static final BigInteger EXPONENT = new BigInteger(1, EXPONENT_BYTES);
  static final byte[] MODULUS_BYTES =
      BigIntegerTestUtil.ensureLeadingZeroBit(
          Base64.urlSafeDecode(
              "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx"
                  + "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs"
                  + "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH"
                  + "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV"
                  + "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8"
                  + "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"));
  static final BigInteger MODULUS = new BigInteger(1, MODULUS_BYTES);
  static final byte[] P_BYTES =
      BigIntegerTestUtil.ensureLeadingZeroBit(
          Base64.urlSafeDecode(
              "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi"
                  + "YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG"
                  + "BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc"));
  static final BigInteger P = new BigInteger(1, P_BYTES);
  static final byte[] Q_BYTES =
      BigIntegerTestUtil.ensureLeadingZeroBit(
          Base64.urlSafeDecode(
              "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa"
                  + "ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA"
                  + "-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"));
  static final BigInteger Q = new BigInteger(1, Q_BYTES);
  static final byte[] D_BYTES =
      BigIntegerTestUtil.ensureLeadingZeroBit(
          Base64.urlSafeDecode(
              "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I"
                  + "jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0"
                  + "BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn"
                  + "439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT"
                  + "CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh"
                  + "BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"));
  static final BigInteger D = new BigInteger(1, D_BYTES);
  static final byte[] DP_BYTES =
      BigIntegerTestUtil.ensureLeadingZeroBit(
          Base64.urlSafeDecode(
              "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q"
                  + "CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb"
                  + "34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0"));
  static final BigInteger DP = new BigInteger(1, DP_BYTES);
  static final byte[] DQ_BYTES =
      BigIntegerTestUtil.ensureLeadingZeroBit(
          Base64.urlSafeDecode(
              "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa"
                  + "7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky"
                  + "NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU"));
  static final BigInteger DQ = new BigInteger(1, DQ_BYTES);
  static final byte[] Q_INV_BYTES =
      BigIntegerTestUtil.ensureLeadingZeroBit(
          Base64.urlSafeDecode(
              "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o"
                  + "y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU"
                  + "W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"));
  static final BigInteger Q_INV = new BigInteger(1, Q_INV_BYTES);

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  private static final class AlgorithmTuple {
    final JwtRsaSsaPkcs1Parameters.Algorithm algorithm;
    final JwtRsaSsaPkcs1Algorithm protoAlgorithm;

    AlgorithmTuple(
        JwtRsaSsaPkcs1Parameters.Algorithm algorithm, JwtRsaSsaPkcs1Algorithm protoAlgorithm) {
      this.algorithm = algorithm;
      this.protoAlgorithm = protoAlgorithm;
    }
  }

  @DataPoints("algorithms")
  public static final AlgorithmTuple[] ALGORITHMS =
      new AlgorithmTuple[] {
        new AlgorithmTuple(JwtRsaSsaPkcs1Parameters.Algorithm.RS256, JwtRsaSsaPkcs1Algorithm.RS256),
        new AlgorithmTuple(JwtRsaSsaPkcs1Parameters.Algorithm.RS384, JwtRsaSsaPkcs1Algorithm.RS384),
        new AlgorithmTuple(JwtRsaSsaPkcs1Parameters.Algorithm.RS512, JwtRsaSsaPkcs1Algorithm.RS512),
      };

  @BeforeClass
  public static void setUp() throws Exception {
    JwtRsaSsaPkcs1ProtoSerialization.register(registry);
  }

  @Theory
  public void serializeParseParameters_kidStrategyIgnored_works(
      @FromDataPoints("algorithms") AlgorithmTuple algorithmTuple) throws Exception {
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
            .setAlgorithm(algorithmTuple.algorithm)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            JwtRsaSsaPkcs1KeyFormat.newBuilder()
                .setVersion(0)
                .setAlgorithm(algorithmTuple.protoAlgorithm)
                .setModulusSizeInBits(2048)
                .setPublicExponent(
                    ByteString.copyFrom(
                        BigIntegerEncoding.toBigEndianBytes(BigInteger.valueOf(65537))))
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(JwtRsaSsaPkcs1KeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_kidStrategyBase64_works() throws Exception {
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.TINK,
            JwtRsaSsaPkcs1KeyFormat.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtRsaSsaPkcs1Algorithm.RS256)
                .setModulusSizeInBits(2048)
                .setPublicExponent(ByteString.copyFrom(EXPONENT_BYTES))
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(JwtRsaSsaPkcs1KeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParameters_kidStrategyCustom_cannotBeSerialized_throws() throws Exception {
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.CUSTOM)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS512)
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
            JwtRsaSsaPkcs1KeyFormat.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtRsaSsaPkcs1Algorithm.RS512)
                .setModulusSizeInBits(2048)
                .setPublicExponent(ByteString.copyFrom(EXPONENT_BYTES))
                .build());
    assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
  }

  @Theory
  public void serializeParsePublicKey_kidIgnored_equal(
      @FromDataPoints("algorithms") AlgorithmTuple algorithmTuple) throws Exception {
    JwtRsaSsaPkcs1PublicKey key =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(
                JwtRsaSsaPkcs1Parameters.builder()
                    .setModulusSizeBits(2048)
                    .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
                    .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
                    .setAlgorithm(algorithmTuple.algorithm)
                    .build())
            .setModulus(MODULUS)
            .build();
    com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey protoPublicKey =
        com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(algorithmTuple.protoAlgorithm)
            .setN(ByteString.copyFrom(MODULUS_BYTES))
            .setE(ByteString.copyFrom(EXPONENT_BYTES))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.equalsKey(key)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, /* access= */ null);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey.parser(), serialized, serialization);
  }

  @Test
  public void serializeParsePublicKey_kidCustom_equal() throws Exception {
    JwtRsaSsaPkcs1PublicKey key =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(
                JwtRsaSsaPkcs1Parameters.builder()
                    .setModulusSizeBits(2048)
                    .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
                    .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.CUSTOM)
                    .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
                    .build())
            .setModulus(MODULUS)
            .setCustomKid("myCustomKid")
            .build();
    com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey protoPublicKey =
        com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(JwtRsaSsaPkcs1Algorithm.RS256)
            .setN(ByteString.copyFrom(MODULUS_BYTES))
            .setE(ByteString.copyFrom(EXPONENT_BYTES))
            .setCustomKid(CustomKid.newBuilder().setValue("myCustomKid").build())
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.equalsKey(key)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, /* access= */ null);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey.parser(), serialized, serialization);
  }

  @Test
  public void serializeParsePublicKey_base64Kid_equal() throws Exception {
    JwtRsaSsaPkcs1PublicKey key =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(
                JwtRsaSsaPkcs1Parameters.builder()
                    .setModulusSizeBits(2048)
                    .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
                    .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                    .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
                    .build())
            .setModulus(MODULUS)
            .setIdRequirement(12345)
            .build();

    com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey protoPublicKey =
        com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(JwtRsaSsaPkcs1Algorithm.RS256)
            .setN(ByteString.copyFrom(MODULUS_BYTES))
            .setE(ByteString.copyFrom(EXPONENT_BYTES))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 12345);

    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.equalsKey(key)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, /* access= */ null);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey.parser(), serialized, serialization);
  }

  @Test
  public void parsePublicKey_crunchy_cannotBeParsed_throws() throws Exception {
    com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey protoPublicKey =
        com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(JwtRsaSsaPkcs1Algorithm.RS256)
            .setN(ByteString.copyFrom(MODULUS_BYTES))
            .setE(ByteString.copyFrom(EXPONENT_BYTES))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.CRUNCHY,
            /* idRequirement= */ 12345);

    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
  }

  @Test
  public void parsePublicKey_tinkAndCustomKeyId_throws() throws Exception {
    com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey protoPublicKey =
        com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(JwtRsaSsaPkcs1Algorithm.RS256)
            .setN(ByteString.copyFrom(MODULUS_BYTES))
            .setE(ByteString.copyFrom(EXPONENT_BYTES))
            .setCustomKid(CustomKid.newBuilder().setValue("WillNotParseWithTINK").build())
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 12345);

    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
  }

  @Test
  public void parsePublicKey_wrongVersion_throws() throws Exception {
    com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey protoPublicKey =
        com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey.newBuilder()
            .setVersion(1)
            .setAlgorithm(JwtRsaSsaPkcs1Algorithm.RS256)
            .setN(ByteString.copyFrom(MODULUS_BYTES))
            .setE(ByteString.copyFrom(EXPONENT_BYTES))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 12345);

    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
  }

  @Test
  public void parsePublicKey_unknownAlgorithm_throws() throws Exception {
    com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey protoPublicKey =
        com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey.newBuilder()
            .setVersion(1)
            .setN(ByteString.copyFrom(MODULUS_BYTES))
            .setE(ByteString.copyFrom(EXPONENT_BYTES))
            .setAlgorithm(JwtRsaSsaPkcs1Algorithm.RS_UNKNOWN)
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 12345);

    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
  }

  @Test
  public void serializeParsePrivateKey_kidIgnored_equal() throws Exception {
    JwtRsaSsaPkcs1PublicKey publicKey =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(
                JwtRsaSsaPkcs1Parameters.builder()
                    .setModulusSizeBits(2048)
                    .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
                    .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
                    .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
                    .build())
            .setModulus(MODULUS)
            .build();
    JwtRsaSsaPkcs1PrivateKey privateKey =
        JwtRsaSsaPkcs1PrivateKey.builder()
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

    com.google.crypto.tink.proto.JwtRsaSsaPkcs1PrivateKey protoPrivateKey =
        com.google.crypto.tink.proto.JwtRsaSsaPkcs1PrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(
                com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey.newBuilder()
                    .setVersion(0)
                    .setAlgorithm(JwtRsaSsaPkcs1Algorithm.RS256)
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
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
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
        com.google.crypto.tink.proto.JwtRsaSsaPkcs1PrivateKey.parser(), serialized, serialization);
  }

  @Test
  public void parsePrivateKey_invalidVersion_throws() throws Exception {
    com.google.crypto.tink.proto.JwtRsaSsaPkcs1PrivateKey protoPrivateKey =
        com.google.crypto.tink.proto.JwtRsaSsaPkcs1PrivateKey.newBuilder()
            .setVersion(1)
            .setPublicKey(
                com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey.newBuilder()
                    .setVersion(0)
                    .setAlgorithm(JwtRsaSsaPkcs1Algorithm.RS256)
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
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
            protoPrivateKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }

  @Test
  public void serializePrivateKey_noSecretKeyAccess_throws() throws Exception {
    JwtRsaSsaPkcs1PublicKey publicKey =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(
                JwtRsaSsaPkcs1Parameters.builder()
                    .setModulusSizeBits(2048)
                    .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
                    .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
                    .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
                    .build())
            .setModulus(MODULUS)
            .build();
    JwtRsaSsaPkcs1PrivateKey privateKey =
        JwtRsaSsaPkcs1PrivateKey.builder()
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

  @Test
  public void parsePrivateKey_noSecretKeyAccess_throws() throws Exception {
    com.google.crypto.tink.proto.JwtRsaSsaPkcs1PrivateKey protoPrivateKey =
        com.google.crypto.tink.proto.JwtRsaSsaPkcs1PrivateKey.newBuilder()
            .setVersion(1)
            .setPublicKey(
                com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey.newBuilder()
                    .setVersion(0)
                    .setAlgorithm(JwtRsaSsaPkcs1Algorithm.RS256)
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
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
            protoPrivateKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
  }
}
