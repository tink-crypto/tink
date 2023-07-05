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

package com.google.crypto.tink.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class RandomWithoutConscryptTest {

  @Test
  public void validateUsesConscrypt_onlyWorksOnAndroid() throws Exception {
    if (TestUtil.isAndroid()) {
      // Android uses Conscrypt by default.
      Random.validateUsesConscrypt();
    } else {
      assertThrows(GeneralSecurityException.class, Random::validateUsesConscrypt);
    }
  }

  @Test
  public void randBytes_works() throws Exception {
    assertThat(Random.randBytes(10)).hasLength(10);
  }

  @Test
  public void randIntWithMax_works() throws Exception {
    assertThat(Random.randInt(5)).isLessThan(5);
  }

  @Test
  public void randInt_works() throws Exception {
    int unused = Random.randInt();
  }

  @Test
  public void randBytes_areDifferent() throws Exception {
    assertThat(Random.randBytes(10)).isNotEqualTo(Random.randBytes(10));
  }

  @Test
  public void randdomBytesInDifferentThreads_areDifferent() throws Exception {
    ArrayList<Thread> threads = new ArrayList<>();
    final byte[] b0 = new byte[10];
    final byte[] b1 = new byte[10];
    threads.add(
        new Thread() {
          @Override
          public void run() {
            System.arraycopy(Random.randBytes(10), 0, b0, 0, 10);
          }
        });
    threads.add(
        new Thread() {
          @Override
          public void run() {
            System.arraycopy(Random.randBytes(10), 0, b1, 0, 10);
          }
        });
    for (Thread thread : threads) {
      thread.start();
    }
    for (Thread thread : threads) {
      thread.join();
    }
    assertThat(b0).isNotEqualTo(b1);
  }
}
