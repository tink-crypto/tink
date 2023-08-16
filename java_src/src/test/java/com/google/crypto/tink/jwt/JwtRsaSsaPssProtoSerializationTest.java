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
import com.google.crypto.tink.proto.JwtRsaSsaPssAlgorithm;
import com.google.crypto.tink.proto.JwtRsaSsaPssKeyFormat;
import com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey.CustomKid;
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
public final class JwtRsaSsaPssProtoSerializationTest {
  private static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey";

  // Test vector from https://www.rfc-editor.org/rfc/rfc7517#appendix-C.1
  static final byte[] EXPONENT_BYTES =
      BigIntegerTestUtil.ensureLeadingZeroBit(Base64.urlSafeDecode("AQAB"));
  static final BigInteger EXPONENT = new BigInteger(1, EXPONENT_BYTES);
  static final byte[] MODULUS_BYTES =
      BigIntegerTestUtil.ensureLeadingZeroBit(
          Base64.urlSafeDecode(
              "t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRy"
                  + "O125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP"
                  + "8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0"
                  + "Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0X"
                  + "OC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1"
                  + "_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q"));
  static final BigInteger MODULUS = new BigInteger(1, MODULUS_BYTES);
  static final byte[] P_BYTES =
      BigIntegerTestUtil.ensureLeadingZeroBit(
          Base64.urlSafeDecode(
              "2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHf"
                  + "QP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8"
                  + "UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws"));
  static final BigInteger P = new BigInteger(1, P_BYTES);
  static final byte[] Q_BYTES =
      BigIntegerTestUtil.ensureLeadingZeroBit(
          Base64.urlSafeDecode(
              "1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6I"
                  + "edis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYK"
                  + "rYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s"));
  static final BigInteger Q = new BigInteger(1, Q_BYTES);
  static final byte[] D_BYTES =
      BigIntegerTestUtil.ensureLeadingZeroBit(
          Base64.urlSafeDecode(
              "GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfS"
                  + "NkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9U"
                  + "vqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnu"
                  + "ToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqADC6p1M3h33tsu"
                  + "rY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWmeRDkK2a"
                  + "hecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ"));
  static final BigInteger D = new BigInteger(1, D_BYTES);
  static final byte[] DP_BYTES =
      BigIntegerTestUtil.ensureLeadingZeroBit(
          Base64.urlSafeDecode(
              "KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwKqvVDq3"
                  + "tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_lhqigI4y_kqS1w"
                  + "Y52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRViD6c"));
  static final BigInteger DP = new BigInteger(1, DP_BYTES);
  static final byte[] DQ_BYTES =
      BigIntegerTestUtil.ensureLeadingZeroBit(
          Base64.urlSafeDecode(
              "AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9"
                  + "GQTB9yqpDoYaN06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBy"
                  + "mXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEAu_lRFCOJ3xDea-ots"));
  static final BigInteger DQ = new BigInteger(1, DQ_BYTES);
  static final byte[] Q_INV_BYTES =
      BigIntegerTestUtil.ensureLeadingZeroBit(
          Base64.urlSafeDecode(
              "lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqq"
                  + "abu9V0-Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0o"
                  + "Yu_neotgQ0hzbI5gry7ajdYy9-2lNx_76aBZoOUu9HCJ-UsfSOI8"));
  static final BigInteger Q_INV = new BigInteger(1, Q_INV_BYTES);

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  private static final class AlgorithmTuple {
    final JwtRsaSsaPssParameters.Algorithm algorithm;
    final JwtRsaSsaPssAlgorithm protoAlgorithm;

    AlgorithmTuple(
        JwtRsaSsaPssParameters.Algorithm algorithm, JwtRsaSsaPssAlgorithm protoAlgorithm) {
      this.algorithm = algorithm;
      this.protoAlgorithm = protoAlgorithm;
    }
  }

  @DataPoints("algorithms")
  public static final AlgorithmTuple[] ALGORITHMS =
      new AlgorithmTuple[] {
        new AlgorithmTuple(JwtRsaSsaPssParameters.Algorithm.PS256, JwtRsaSsaPssAlgorithm.PS256),
        new AlgorithmTuple(JwtRsaSsaPssParameters.Algorithm.PS384, JwtRsaSsaPssAlgorithm.PS384),
        new AlgorithmTuple(JwtRsaSsaPssParameters.Algorithm.PS512, JwtRsaSsaPssAlgorithm.PS512),
      };

  @BeforeClass
  public static void setUp() throws Exception {
    JwtRsaSsaPssProtoSerialization.register(registry);
  }

  @Theory
  public void serializeParseParameters_kidStrategyIgnored_works(
      @FromDataPoints("algorithms") AlgorithmTuple algorithmTuple) throws Exception {
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .setAlgorithm(algorithmTuple.algorithm)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            JwtRsaSsaPssKeyFormat.newBuilder()
                .setVersion(0)
                .setAlgorithm(algorithmTuple.protoAlgorithm)
                .setModulusSizeInBits(2048)
                .setPublicExponent(
                    ByteString.copyFrom(
                        BigIntegerEncoding.toBigEndianBytes(BigInteger.valueOf(65537))))
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(JwtRsaSsaPssKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_kidStrategyBase64_works() throws Exception {
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.TINK,
            JwtRsaSsaPssKeyFormat.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtRsaSsaPssAlgorithm.PS256)
                .setModulusSizeInBits(2048)
                .setPublicExponent(ByteString.copyFrom(EXPONENT_BYTES))
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(JwtRsaSsaPssKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParameters_kidStrategyCustom_cannotBeSerialized_throws() throws Exception {
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.CUSTOM)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS512)
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
            JwtRsaSsaPssKeyFormat.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtRsaSsaPssAlgorithm.PS512)
                .setModulusSizeInBits(2048)
                .setPublicExponent(ByteString.copyFrom(EXPONENT_BYTES))
                .build());
    assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
  }

  @Theory
  public void serializeParsePublicKey_kidIgnored_equal(
      @FromDataPoints("algorithms") AlgorithmTuple algorithmTuple) throws Exception {
    JwtRsaSsaPssPublicKey key =
        JwtRsaSsaPssPublicKey.builder()
            .setParameters(
                JwtRsaSsaPssParameters.builder()
                    .setModulusSizeBits(2048)
                    .setPublicExponent(JwtRsaSsaPssParameters.F4)
                    .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                    .setAlgorithm(algorithmTuple.algorithm)
                    .build())
            .setModulus(MODULUS)
            .build();
    com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey protoPublicKey =
        com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(algorithmTuple.protoAlgorithm)
            .setN(ByteString.copyFrom(MODULUS_BYTES))
            .setE(ByteString.copyFrom(EXPONENT_BYTES))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.equalsKey(key)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, /* access= */ null);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey.parser(), serialized, serialization);
  }

  @Test
  public void serializeParsePublicKey_kidCustom_equal() throws Exception {
    JwtRsaSsaPssPublicKey key =
        JwtRsaSsaPssPublicKey.builder()
            .setParameters(
                JwtRsaSsaPssParameters.builder()
                    .setModulusSizeBits(2048)
                    .setPublicExponent(JwtRsaSsaPssParameters.F4)
                    .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.CUSTOM)
                    .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                    .build())
            .setModulus(MODULUS)
            .setCustomKid("myCustomKid")
            .build();
    com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey protoPublicKey =
        com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(JwtRsaSsaPssAlgorithm.PS256)
            .setN(ByteString.copyFrom(MODULUS_BYTES))
            .setE(ByteString.copyFrom(EXPONENT_BYTES))
            .setCustomKid(CustomKid.newBuilder().setValue("myCustomKid").build())
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.equalsKey(key)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, /* access= */ null);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey.parser(), serialized, serialization);
  }

  @Test
  public void serializeParsePublicKey_base64Kid_equal() throws Exception {
    JwtRsaSsaPssPublicKey key =
        JwtRsaSsaPssPublicKey.builder()
            .setParameters(
                JwtRsaSsaPssParameters.builder()
                    .setModulusSizeBits(2048)
                    .setPublicExponent(JwtRsaSsaPssParameters.F4)
                    .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                    .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                    .build())
            .setModulus(MODULUS)
            .setIdRequirement(12345)
            .build();

    com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey protoPublicKey =
        com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(JwtRsaSsaPssAlgorithm.PS256)
            .setN(ByteString.copyFrom(MODULUS_BYTES))
            .setE(ByteString.copyFrom(EXPONENT_BYTES))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 12345);

    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.equalsKey(key)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, /* access= */ null);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey.parser(), serialized, serialization);
  }

  @Test
  public void parsePublicKey_crunchy_cannotBeParsed_throws() throws Exception {
    com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey protoPublicKey =
        com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(JwtRsaSsaPssAlgorithm.PS256)
            .setN(ByteString.copyFrom(MODULUS_BYTES))
            .setE(ByteString.copyFrom(EXPONENT_BYTES))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.CRUNCHY,
            /* idRequirement= */ 12345);

    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
  }

  @Test
  public void parsePublicKey_tinkAndCustomKeyId_throws() throws Exception {
    com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey protoPublicKey =
        com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(JwtRsaSsaPssAlgorithm.PS256)
            .setN(ByteString.copyFrom(MODULUS_BYTES))
            .setE(ByteString.copyFrom(EXPONENT_BYTES))
            .setCustomKid(CustomKid.newBuilder().setValue("WillNotParseWithTINK").build())
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 12345);

    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
  }

  @Test
  public void parsePublicKey_wrongVersion_throws() throws Exception {
    com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey protoPublicKey =
        com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey.newBuilder()
            .setVersion(1)
            .setAlgorithm(JwtRsaSsaPssAlgorithm.PS256)
            .setN(ByteString.copyFrom(MODULUS_BYTES))
            .setE(ByteString.copyFrom(EXPONENT_BYTES))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 12345);

    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
  }

  @Test
  public void parsePublicKey_unknownAlgorithm_throws() throws Exception {
    com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey protoPublicKey =
        com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey.newBuilder()
            .setVersion(1)
            .setN(ByteString.copyFrom(MODULUS_BYTES))
            .setE(ByteString.copyFrom(EXPONENT_BYTES))
            .setAlgorithm(JwtRsaSsaPssAlgorithm.PS_UNKNOWN)
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 12345);

    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
  }

  @Test
  public void serializeParsePrivateKey_kidIgnored_equal() throws Exception {
    JwtRsaSsaPssPublicKey publicKey =
        JwtRsaSsaPssPublicKey.builder()
            .setParameters(
                JwtRsaSsaPssParameters.builder()
                    .setModulusSizeBits(2048)
                    .setPublicExponent(JwtRsaSsaPssParameters.F4)
                    .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                    .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                    .build())
            .setModulus(MODULUS)
            .build();
    JwtRsaSsaPssPrivateKey privateKey =
        JwtRsaSsaPssPrivateKey.builder()
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

    com.google.crypto.tink.proto.JwtRsaSsaPssPrivateKey protoPrivateKey =
        com.google.crypto.tink.proto.JwtRsaSsaPssPrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(
                com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey.newBuilder()
                    .setVersion(0)
                    .setAlgorithm(JwtRsaSsaPssAlgorithm.PS256)
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
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey",
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
        com.google.crypto.tink.proto.JwtRsaSsaPssPrivateKey.parser(), serialized, serialization);
  }

  @Test
  public void parsePrivateKey_invalidVersion_throws() throws Exception {
    com.google.crypto.tink.proto.JwtRsaSsaPssPrivateKey protoPrivateKey =
        com.google.crypto.tink.proto.JwtRsaSsaPssPrivateKey.newBuilder()
            .setVersion(1)
            .setPublicKey(
                com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey.newBuilder()
                    .setVersion(0)
                    .setAlgorithm(JwtRsaSsaPssAlgorithm.PS256)
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
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey",
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
    JwtRsaSsaPssPublicKey publicKey =
        JwtRsaSsaPssPublicKey.builder()
            .setParameters(
                JwtRsaSsaPssParameters.builder()
                    .setModulusSizeBits(2048)
                    .setPublicExponent(JwtRsaSsaPssParameters.F4)
                    .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                    .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                    .build())
            .setModulus(MODULUS)
            .build();
    JwtRsaSsaPssPrivateKey privateKey =
        JwtRsaSsaPssPrivateKey.builder()
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
    com.google.crypto.tink.proto.JwtRsaSsaPssPrivateKey protoPrivateKey =
        com.google.crypto.tink.proto.JwtRsaSsaPssPrivateKey.newBuilder()
            .setVersion(1)
            .setPublicKey(
                com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey.newBuilder()
                    .setVersion(0)
                    .setAlgorithm(JwtRsaSsaPssAlgorithm.PS256)
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
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey",
            protoPrivateKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
  }
}
