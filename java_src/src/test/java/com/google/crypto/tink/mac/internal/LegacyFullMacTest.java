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
import com.google.crypto.tink.PrimitiveWrapper;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveSet;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.internal.HmacTestUtil.HmacTestVector;
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

  @BeforeClass
  public static void setUp() throws Exception {
    LegacyHmacTestKeyManager.register();
    HmacProtoSerialization.register();
    // This is to ensure that the tests indeed get the objects we are testing for.
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(
            PrimitiveConstructor.create(
                (LegacyProtoKey key) -> (LegacyFullMac) LegacyFullMac.create(key),
                LegacyProtoKey.class,
                LegacyFullMac.class));
    TestLegacyMacWrapper.register();

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
    LegacyProtoKey key = getLegacyProtoKey(t.key);
    Mac hmac = LegacyFullMac.create(key);

    assertThat(hmac.computeMac(t.message)).isEqualTo(t.tag);
  }

  @Theory
  public void verifyHmac_isCorrect(@FromDataPoints("allHmacTestVectors") HmacTestVector t)
      throws Exception {
    LegacyProtoKey key = getLegacyProtoKey(t.key);
    Mac hmac = LegacyFullMac.create(key);

    hmac.verifyMac(t.tag, t.message);
  }

  @Theory
  public void verifyHmac_throwsOnWrongTag(
      @FromDataPoints("failingHmacTestVectors") HmacTestVector t) throws Exception {
    LegacyProtoKey key = getLegacyProtoKey(t.key);
    Mac hmac = LegacyFullMac.create(key);

    assertThrows(GeneralSecurityException.class, () -> hmac.verifyMac(t.tag, t.message));
  }

  private static LegacyProtoKey getLegacyProtoKey(HmacKey hmacKey) throws GeneralSecurityException {
    return new LegacyProtoKey(
        MutableSerializationRegistry.globalInstance()
            .serializeKey(hmacKey, ProtoKeySerialization.class, InsecureSecretKeyAccess.get()),
        InsecureSecretKeyAccess.get());
  }

  private static final class TestLegacyMacWrapper implements PrimitiveWrapper<LegacyFullMac, Mac> {
    static final TestLegacyMacWrapper WRAPPER = new TestLegacyMacWrapper();

    @Override
    public LegacyFullMac wrap(PrimitiveSet<LegacyFullMac> primitiveSet)
        throws GeneralSecurityException {
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
