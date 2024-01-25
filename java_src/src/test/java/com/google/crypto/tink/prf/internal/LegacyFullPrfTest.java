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

package com.google.crypto.tink.prf.internal;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.prf.HmacPrfKey;
import com.google.crypto.tink.prf.Prf;
import com.google.crypto.tink.prf.internal.LegacyHmacPrfTestUtil.HmacLegacyPrfTestVector;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public class LegacyFullPrfTest {
  @DataPoints("hmacPrfTestVectors")
  public static final HmacLegacyPrfTestVector[] HMAC_LEGACY_PRF_TEST_VECTOR =
      LegacyHmacPrfTestUtil.HMAC_LEGACY_PRF_TEST_VECTORS;

  @BeforeClass
  public static void setUp() throws Exception {
    LegacyHmacPrfTestKeyManager.register();
    HmacPrfProtoSerialization.register();
    // This is to ensure that the tests indeed get the objects we are testing for.
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(
            PrimitiveConstructor.create(
                (LegacyProtoKey key) -> (LegacyFullPrf) LegacyFullPrf.create(key),
                LegacyProtoKey.class,
                LegacyFullPrf.class));
  }

  @Theory
  public void compute_isCorrect(@FromDataPoints("hmacPrfTestVectors") HmacLegacyPrfTestVector t)
      throws Exception {
    Prf prf = LegacyFullPrf.create(getLegacyProtoKey(t.key));

    assertThat(prf.compute(t.message, t.tag.length)).isEqualTo(t.tag);
  }

  private static LegacyProtoKey getLegacyProtoKey(HmacPrfKey hmacPrfKey)
      throws GeneralSecurityException {
    return new LegacyProtoKey(
        MutableSerializationRegistry.globalInstance()
            .serializeKey(hmacPrfKey, ProtoKeySerialization.class, InsecureSecretKeyAccess.get()),
        InsecureSecretKeyAccess.get());
  }
}
