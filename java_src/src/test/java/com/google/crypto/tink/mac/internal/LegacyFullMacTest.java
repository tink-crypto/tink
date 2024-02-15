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

package com.google.crypto.tink.mac.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.internal.EnumTypeProtoConverter;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.HmacParameters;
import com.google.crypto.tink.mac.HmacParameters.Variant;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.mac.internal.HmacTestUtil.HmacTestVector;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.BeforeClass;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public class LegacyFullMacTest {
  private static final String TYPE_URL = "type.googleapis.com/custom.HmacKey";
  private static final EnumTypeProtoConverter<OutputPrefixType, Variant>
      OUTPUT_PREFIX_TYPE_CONVERTER =
          EnumTypeProtoConverter.<OutputPrefixType, HmacParameters.Variant>builder()
              .add(OutputPrefixType.RAW, HmacParameters.Variant.NO_PREFIX)
              .add(OutputPrefixType.TINK, HmacParameters.Variant.TINK)
              .add(OutputPrefixType.LEGACY, HmacParameters.Variant.LEGACY)
              .add(OutputPrefixType.CRUNCHY, HmacParameters.Variant.CRUNCHY)
              .build();
  private static final EnumTypeProtoConverter<HashType, HmacParameters.HashType>
      HASH_TYPE_CONVERTER =
          EnumTypeProtoConverter.<HashType, HmacParameters.HashType>builder()
              .add(HashType.SHA1, HmacParameters.HashType.SHA1)
              .add(HashType.SHA224, HmacParameters.HashType.SHA224)
              .add(HashType.SHA256, HmacParameters.HashType.SHA256)
              .add(HashType.SHA384, HmacParameters.HashType.SHA384)
              .add(HashType.SHA512, HmacParameters.HashType.SHA512)
              .build();

  @BeforeClass
  public static void setUp() throws Exception {
    MacConfig.register();
    LegacyHmacTestKeyManager.register();

    hmacImplementationTestVectors =
        Arrays.copyOf(
            HmacTestUtil.HMAC_TEST_VECTORS,
            HmacTestUtil.HMAC_TEST_VECTORS.length + HmacTestUtil.PREFIXED_KEY_TYPES.length);
    System.arraycopy(
        HmacTestUtil.PREFIXED_KEY_TYPES,
        0,
        hmacImplementationTestVectors,
        HmacTestUtil.HMAC_TEST_VECTORS.length,
        HmacTestUtil.PREFIXED_KEY_TYPES.length);
  }

  @DataPoints("failingHmacTestVectors")
  public static final HmacTestVector[] HMAC_FAILING_TEST_VECTORS =
      HmacTestUtil.CREATE_VERIFICATION_FAILS_FAST;

  @DataPoints("allHmacTestVectors")
  public static HmacTestVector[] hmacImplementationTestVectors;

  @Theory
  public void computeHmac_isCorrect(@FromDataPoints("allHmacTestVectors") HmacTestVector t)
      throws Exception {
    Mac hmac = LegacyFullMac.create(getLegacyProtoKey(t.key));

    assertThat(hmac.computeMac(t.message)).isEqualTo(t.tag);
  }

  @Theory
  public void verifyHmac_isCorrect(@FromDataPoints("allHmacTestVectors") HmacTestVector t)
      throws Exception {
    Mac hmac = LegacyFullMac.create(getLegacyProtoKey(t.key));

    hmac.verifyMac(t.tag, t.message);
  }

  @Theory
  public void verifyHmac_throwsOnWrongTag(
      @FromDataPoints("failingHmacTestVectors") HmacTestVector t) throws Exception {
    Mac hmac = LegacyFullMac.create(getLegacyProtoKey(t.key));

    assertThrows(GeneralSecurityException.class, () -> hmac.verifyMac(t.tag, t.message));
  }

  private static LegacyProtoKey getLegacyProtoKey(HmacKey hmacKey) throws GeneralSecurityException {
    return new LegacyProtoKey(
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.HmacKey.newBuilder()
                .setParams(
                    com.google.crypto.tink.proto.HmacParams.newBuilder()
                        .setTagSize(hmacKey.getParameters().getCryptographicTagSizeBytes())
                        .setHash(
                            HASH_TYPE_CONVERTER.toProtoEnum(hmacKey.getParameters().getHashType()))
                        .build())
                .setKeyValue(
                    ByteString.copyFrom(
                        hmacKey
                            .getKeyBytes()
                            .toByteArray(
                                SecretKeyAccess.requireAccess(InsecureSecretKeyAccess.get()))))
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OUTPUT_PREFIX_TYPE_CONVERTER.toProtoEnum(hmacKey.getParameters().getVariant()),
            hmacKey.getIdRequirementOrNull()),
        InsecureSecretKeyAccess.get());
  }
}
