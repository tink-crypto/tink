// Copyright 2018 Google Inc.
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

package com.google.crypto.tink.subtle;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.subtle.Enums.HashType;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for SubtleUtil. */
@RunWith(JUnit4.class)
public final class SubtleUtilTest {
  @Test
  public void testToEcdsaAlgo() throws Exception {
    assertEquals("SHA256withECDSA", SubtleUtil.toEcdsaAlgo(HashType.SHA256));
    assertEquals("SHA512withECDSA", SubtleUtil.toEcdsaAlgo(HashType.SHA512));
    try {
      SubtleUtil.toEcdsaAlgo(HashType.SHA1);
      fail("Invalid hash, should have thrown exception");
    } catch (GeneralSecurityException expected) {
    }
  }

  @Test
  public void testToRsaSsaPkcs1Algo() throws Exception {
    assertEquals("SHA256withRSA", SubtleUtil.toRsaSsaPkcs1Algo(HashType.SHA256));
    assertEquals("SHA512withRSA", SubtleUtil.toRsaSsaPkcs1Algo(HashType.SHA512));
    try {
      SubtleUtil.toRsaSsaPkcs1Algo(HashType.SHA1);
      fail("Invalid hash, should have thrown exception");
    } catch (GeneralSecurityException expected) {
    }
  }

  @Test
  public void testPutAsUnsigedInt_smallNumber() throws Exception {
    ByteBuffer buffer = ByteBuffer.allocate(4);
    SubtleUtil.putAsUnsigedInt(buffer, 0x1122EEFFL);
    assertThat(buffer.array()).isEqualTo(new byte[] {0x11, 0x22, (byte) 0xEE, (byte) 0xFF});
  }

  @Test
  public void testPutAsUnsigedInt_largeNumber() throws Exception {
    ByteBuffer buffer = ByteBuffer.allocate(4);
    SubtleUtil.putAsUnsigedInt(buffer, 0xFFEEDDCCL);
    assertThat(buffer.array())
        .isEqualTo(new byte[] {(byte) 0xFF, (byte) 0xEE, (byte) 0xDD, (byte) 0xCC});
  }

  @Test
  public void testPutAsUnsigedInt_max() throws Exception {
    ByteBuffer buffer = ByteBuffer.allocate(4);
    SubtleUtil.putAsUnsigedInt(buffer, 0xFFFFFFFFL);
    assertThat(buffer.array())
        .isEqualTo(new byte[] {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF});
  }

  @Test
  public void testPutAsUnsigedInt_tooLargeNumber_throws() throws Exception {
    ByteBuffer buffer = ByteBuffer.allocate(4);
    try {
      SubtleUtil.putAsUnsigedInt(buffer, 0xFFFFFFFFL + 1L);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void testPutAsUnsigedInt_minusOne_throws() throws Exception {
    ByteBuffer buffer = ByteBuffer.allocate(4);
    try {
      SubtleUtil.putAsUnsigedInt(buffer, -1);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }
}
