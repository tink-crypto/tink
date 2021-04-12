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

package com.google.crypto.tink.testing;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import org.junit.Before;
import org.junit.Test;
import org.junit.function.ThrowingRunnable;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests some of the more complex functions from TestUtil. */
@RunWith(JUnit4.class)
public class TestUtilTest {
  SecureRandom random;
  final byte[] randomBytes = new byte[512];
  // Correlated to randomBytes: derived by 1 + randomBytes.
  final byte[] correlatedRandomBytes = new byte[512];
  final byte[] moreRandomBytes = new byte[512];
  final ArrayList<Integer> randomIndices = new ArrayList<>(512);

  @Before
  public void startup() throws NoSuchAlgorithmException {
    random = SecureRandom.getInstanceStrong();
    random.setSeed(1234);
    random.nextBytes(randomBytes);
    random.nextBytes(moreRandomBytes);

    for (int i = 0; i < randomBytes.length; i++) {
      correlatedRandomBytes[i] = randomBytes[i];
      randomIndices.add(i);
    }
    Collections.shuffle(randomIndices);
  }

  @Test
  public void testZTestUniformitySucceedsOnRandomData() throws GeneralSecurityException {
    TestUtil.ztestUniformString(randomBytes);
  }

  @Test
  public void testZTestUniformityFailsOnNonRandomData() {
    String msg =
        assertThrows(
                GeneralSecurityException.class,
                new ThrowingRunnable() {
                  @Override
                  public void run() throws Throwable {
                    setValueForNBytes(randomBytes, 256, (byte) 1);
                    TestUtil.ztestUniformString(randomBytes);
                  }
                })
            .getMessage();
    assertThat(msg).contains("Z test for uniformly distributed variable out of bounds");
  }

  @Test
  public void testZTestUniformityFailsOnNonRandomNegativeData() {
    String msg =
        assertThrows(
                GeneralSecurityException.class,
                new ThrowingRunnable() {
                  @Override
                  public void run() throws Throwable {
                    setValueForNBytes(randomBytes, 256, (byte) -120);
                    TestUtil.ztestUniformString(randomBytes);
                  }
                })
            .getMessage();
    assertThat(msg).contains("Z test for uniformly distributed variable out of bounds");
  }

  @Test
  public void testZTestUniformityFailsOnSmallUniformMessage() {
    String msg =
        assertThrows(
                GeneralSecurityException.class,
                new ThrowingRunnable() {
                  @Override
                  public void run() throws Throwable {
                    byte[] allZeros = new byte[16];
                    TestUtil.ztestUniformString(allZeros);
                  }
                })
            .getMessage();
    assertThat(msg).contains("Z test for uniformly distributed variable out of bounds");
  }

  @Test
  public void testZTestUniformityFailsWithTooSmallMessage() {
    String msg =
        assertThrows(
                GeneralSecurityException.class,
                new ThrowingRunnable() {
                  @Override
                  public void run() throws Throwable {
                    byte[] allZeros = new byte[4];
                    TestUtil.ztestUniformString(allZeros);
                  }
                })
            .getMessage();
    assertThat(msg).contains("Use more bytes.");
  }

  @Test
  public void testZTestCrossCorrelationUniformitySucceedsOnRandomData()
      throws GeneralSecurityException {
    TestUtil.ztestCrossCorrelationUniformStrings(randomBytes, moreRandomBytes);
  }

  @Test
  public void testZTestCrossCorrelationUniformityFailsOnCorrelatedData()
      throws GeneralSecurityException {
    String msg =
        assertThrows(
                GeneralSecurityException.class,
                new ThrowingRunnable() {
                  @Override
                  public void run() throws Throwable {
                    TestUtil.ztestCrossCorrelationUniformStrings(
                        randomBytes, correlatedRandomBytes);
                  }
                })
            .getMessage();
    assertThat(msg).contains("Z test for uniformly distributed variable out of bounds");
  }

  @Test
  public void testZTestAutoCorrelationSucceedsOnRandomData() throws GeneralSecurityException {
    TestUtil.ztestAutocorrelationUniformString(randomBytes);
  }

  @Test
  public void testZTestAutoCorrelationFailsOnAutoCorrelatedData() throws GeneralSecurityException {
    byte[] repeatedRandom = new byte[randomBytes.length * 3];
    for (int i = 0; i < 3; i++) {
      System.arraycopy(randomBytes, 0, repeatedRandom, i * randomBytes.length, randomBytes.length);
    }

    String msg =
        assertThrows(
                GeneralSecurityException.class,
                new ThrowingRunnable() {
                  @Override
                  public void run() throws Throwable {
                    TestUtil.ztestAutocorrelationUniformString(repeatedRandom);
                  }
                })
            .getMessage();
    assertThat(msg).contains("Z test for uniformly distributed variable out of bounds");
  }

  private void setValueForNBytes(byte[] input, int numberBytesToSet, byte valueToSet) {
    for (int i = 0; i < numberBytesToSet; i++) {
      input[randomIndices.get(i)] = valueToSet;
    }
  }
}
