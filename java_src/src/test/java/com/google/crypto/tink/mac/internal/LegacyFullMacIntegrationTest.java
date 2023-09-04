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

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.PrimitiveWrapper;
import com.google.crypto.tink.internal.EnumTypeProtoConverter;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.HmacParameters;
import com.google.crypto.tink.mac.internal.HmacTestUtil.HmacTestVector;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Verifies that LegacyFullMac is correctly integrated with the Tink ecosystem. */
@RunWith(Theories.class)
public class LegacyFullMacIntegrationTest {
  private static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.HmacKey";
  private static final EnumTypeProtoConverter<OutputPrefixType, HmacParameters.Variant>
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

  @DataPoints("allHmacTestVectors")
  public static HmacTestVector[] hmacImplementationTestVectors;

  @Theory
  public void endToEnd_works(@FromDataPoints("allHmacTestVectors") HmacTestVector t)
      throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    // This is to ensure that the tests indeed get the objects we are testing for.
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(
            PrimitiveConstructor.create(
                (LegacyProtoKey key) -> (LegacyFullMac) LegacyFullMac.create(key),
                LegacyProtoKey.class,
                LegacyFullMac.class));
    TestLegacyMacWrapper.register();

    KeysetHandle keysetHandle = getKeysetHandleFromKeyNoSerialization(t.key);
    Mac mac = keysetHandle.getPrimitive(Mac.class);

    assertThat(mac).isInstanceOf(LegacyFullMac.class);
    mac.verifyMac(t.tag, t.message);
  }

  @Test
  public void legacyFullMacNotRegistered_fails() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    TestLegacyMacWrapper.register();

    KeysetHandle keysetHandle =
        getKeysetHandleFromKeyNoSerialization(hmacImplementationTestVectors[0].key);

    assertThrows(GeneralSecurityException.class, () -> keysetHandle.getPrimitive(Mac.class));
  }

  private static KeysetHandle getKeysetHandleFromKeyNoSerialization(HmacKey key)
      throws GeneralSecurityException {
    KeyData rawKeyData =
        KeyData.newBuilder()
            .setValue(
                com.google.crypto.tink.proto.HmacKey.newBuilder()
                    .setParams(
                        HmacParams.newBuilder()
                            .setHash(
                                HASH_TYPE_CONVERTER.toProtoEnum(key.getParameters().getHashType()))
                            .setTagSize(key.getParameters().getCryptographicTagSizeBytes())
                            .build())
                    .setKeyValue(
                        ByteString.copyFrom(
                            key.getKeyBytes().toByteArray(InsecureSecretKeyAccess.get())))
                    .build()
                    .toByteString())
            .setTypeUrl(TYPE_URL)
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .build();
    int id = key.getIdRequirementOrNull() == null ? 42 : key.getIdRequirementOrNull();
    Keyset.Key rawKeysetKey =
        Keyset.Key.newBuilder()
            .setKeyData(rawKeyData)
            .setStatus(KeyStatusType.ENABLED)
            .setKeyId(id)
            .setOutputPrefixType(
                OUTPUT_PREFIX_TYPE_CONVERTER.toProtoEnum(key.getParameters().getVariant()))
            .build();
    /* Here, a to-be-removed API (CleartextKeysetHandle) is used due to the need to create the
     * KeysetHandle from a Keyset (and security is of no concern since it's a test).
     *
     * The other way to do this would be through registering only the serialization part of
     * HmacProtoSerialization (without parsing), and then creating the KeysetHandle from the
     * Key object -- however, this seems unnecessarily complicated since this test covers legacy
     * functionality anyway.
     */
    return CleartextKeysetHandle.fromKeyset(
        Keyset.newBuilder().addKey(rawKeysetKey).setPrimaryKeyId(id).build());
  }

  private static final class TestLegacyMacWrapper implements PrimitiveWrapper<LegacyFullMac, Mac> {
    static final TestLegacyMacWrapper WRAPPER = new TestLegacyMacWrapper();

    @Override
    public Mac wrap(PrimitiveSet<LegacyFullMac> primitiveSet)
        throws GeneralSecurityException {
      // This is a dummy test wrapper that act as a proxy to a single primitive object under test.
      return primitiveSet.getPrimary().getFullPrimitive();
    }

    @Override
    public Class<Mac> getPrimitiveClass() {
      return Mac.class;
    }

    @Override
    public Class<LegacyFullMac> getInputPrimitiveClass() {
      return LegacyFullMac.class;
    }

    static void register() throws GeneralSecurityException {
      MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(WRAPPER);
    }
  }
}
