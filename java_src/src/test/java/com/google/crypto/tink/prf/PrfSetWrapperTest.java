// Copyright 2020 Google LLC
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
package com.google.crypto.tink.prf;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.function.ThrowingRunnable;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for PrfSetWrapper. */
@RunWith(JUnit4.class)
public class PrfSetWrapperTest {
  private static final int KEY_SIZE = 32;

  @BeforeClass
  public static void setUp() throws Exception {
    PrfConfig.register();
  }

  @Test
  public void testSmallPlaintextWithRawKey() throws Exception {
    byte[] keyValue = Random.randBytes(KEY_SIZE);
    Keyset.Key primary =
        TestUtil.createKey(
            TestUtil.createPrfKeyData(keyValue),
            /* keyId= */ 5,
            KeyStatusType.ENABLED,
            OutputPrefixType.RAW);
    PrimitiveSet<Prf> primitives =
        TestUtil.createPrimitiveSet(TestUtil.createKeyset(primary), Prf.class);
    byte[] plaintext = "blah".getBytes(UTF_8);

    PrfSet prfSet = new PrfSetWrapper().wrap(primitives);
    byte[] prs = prfSet.computePrimary(plaintext, 12);
    byte[] prs2 = prfSet.getPrfs().get(5).compute(plaintext, 12);

    assertEquals(5, prfSet.getPrimaryId());
    assertThat(prfSet.getPrfs()).hasSize(1);
    assertThat(prs).hasLength(12);
    assertArrayEquals(prs2, prs);
  }

  @Test
  public void testSmallPlaintextWithMultipleKeys() throws Exception {
    byte[] primaryKeyValue = Random.randBytes(KEY_SIZE);
    Keyset.Key primary =
        TestUtil.createKey(
            TestUtil.createPrfKeyData(primaryKeyValue),
            /* keyId= */ 5,
            KeyStatusType.ENABLED,
            OutputPrefixType.RAW);
    byte[] secondaryKeyValue = Random.randBytes(KEY_SIZE);
    Keyset.Key secondary =
        TestUtil.createKey(
            TestUtil.createPrfKeyData(secondaryKeyValue),
            /* keyId= */ 6,
            KeyStatusType.ENABLED,
            OutputPrefixType.RAW);
    PrimitiveSet<Prf> primitives =
        TestUtil.createPrimitiveSet(TestUtil.createKeyset(primary, secondary), Prf.class);
    byte[] plaintext = "blah".getBytes(UTF_8);

    PrfSet prfSet = new PrfSetWrapper().wrap(primitives);
    byte[] prsPrimary = prfSet.computePrimary(plaintext, 12);
    byte[] prs5 = prfSet.getPrfs().get(5).compute(plaintext, 12);
    byte[] prs6 = prfSet.getPrfs().get(6).compute(plaintext, 12);

    assertEquals(5, prfSet.getPrimaryId());
    assertThat(prfSet.getPrfs()).hasSize(2);
    assertThat(prsPrimary).hasLength(12);
    assertArrayEquals(prs5, prsPrimary);
    assertThat(prsPrimary).isNotEqualTo(prs6);
  }

    @Test
    public void testWrapEmptyThrows() throws Exception {
      final PrimitiveSet<Prf> primitiveSet = PrimitiveSet.newBuilder(Prf.class).build();

      assertThrows(
          GeneralSecurityException.class,
          new ThrowingRunnable() {
            @Override
            public void run() throws Throwable {
              new PrfSetWrapper().wrap(primitiveSet);
            }
          });
    }

  @Test
  public void testWrapNoPrimaryThrows() throws Exception {
    byte[] primaryKeyValue = Random.randBytes(KEY_SIZE);
    Keyset.Key primary =
        TestUtil.createKey(
            TestUtil.createPrfKeyData(primaryKeyValue),
            /* keyId= */ 5,
            KeyStatusType.ENABLED,
            OutputPrefixType.RAW);
    final Prf unusedPrf =
        new Prf() {
          @Override
          public byte[] compute(byte[] input, int outputLength) throws GeneralSecurityException {
            return new byte[0];
          }
        };
    final PrimitiveSet<Prf> primitiveSet =
        PrimitiveSet.newBuilder(Prf.class).addPrimitive(unusedPrf, primary).build();
    // Note: Added a primary key but did not call primitiveSet.setPrimary().

    assertThrows(
        GeneralSecurityException.class,
        new ThrowingRunnable() {
          @Override
          public void run() throws Throwable {
            new PrfSetWrapper().wrap(primitiveSet);
          }
        });
  }
}
