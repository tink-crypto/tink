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

package com.google.crypto.tink.hybrid.subtle;

import static com.google.common.truth.Truth.assertThat;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test for RsaKem * */
@RunWith(JUnit4.class)
public final class RsaKemTest {
  private static final Charset UTF_8 = Charset.forName("UTF-8");

  @Test
  public void bigIntToByteArray_approximate() throws Exception {
    int expectedSize = 2048;
    BigInteger bigInt = new BigInteger(2048, new Random());
    byte[] bigIntBytes = RsaKem.bigIntToByteArray(bigInt, expectedSize);

    assertThat(bigIntBytes).hasLength(expectedSize);
    assertThat(new BigInteger(1, bigIntBytes)).isEqualTo(bigInt);
  }

  @Test
  public void bigIntToByteArray_withALeadingZero() throws Exception {
    int expectedSize = 2048;
    BigInteger bigIntWithALeadingZero;
    while (true) {
      bigIntWithALeadingZero = new BigInteger(2048, new Random());
      byte[] r = bigIntWithALeadingZero.toByteArray();
      if (r[0] == 0) {
        break;
      }
    }

    byte[] modBytes = RsaKem.bigIntToByteArray(bigIntWithALeadingZero, expectedSize);
    assertThat(modBytes).hasLength(expectedSize);
    assertThat(new BigInteger(1, modBytes)).isEqualTo(bigIntWithALeadingZero);
  }

  @Test
  public void bigIntToByteArray_small() throws Exception {
    int expectedSize = 2048;
    BigInteger smallInt = BigInteger.valueOf(42L);
    byte[] smallIntBytes = RsaKem.bigIntToByteArray(smallInt, expectedSize);

    assertThat(smallIntBytes).hasLength(expectedSize);
    assertThat(new BigInteger(1, smallIntBytes)).isEqualTo(smallInt);
  }

  @Test
  public void generateSecret() throws Exception {
    BigInteger max = new BigInteger(2048, new Random());
    int maxSizeInBytes = RsaKem.bigIntSizeInBytes(max);

    Set<String> secrets = new TreeSet<>();
    for (int i = 0; i < 100; i++) {
      byte[] secret = RsaKem.generateSecret(max);
      BigInteger secretBigInt = new BigInteger(1, secret);
      secrets.add(new String(secret, UTF_8));

      assertThat(secret).hasLength(maxSizeInBytes);
      assertThat(secretBigInt.signum()).isEqualTo(1);
      assertThat(secretBigInt.compareTo(max)).isLessThan(0);
    }
    assertThat(secrets).hasSize(100);
  }
}
