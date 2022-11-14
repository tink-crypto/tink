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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.subtle.Enums.HashType;
import java.math.BigInteger;
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
    assertThrows(GeneralSecurityException.class, () -> SubtleUtil.toEcdsaAlgo(HashType.SHA1));
  }

  @Test
  public void testToRsaSsaPkcs1Algo() throws Exception {
    assertEquals("SHA256withRSA", SubtleUtil.toRsaSsaPkcs1Algo(HashType.SHA256));
    assertEquals("SHA512withRSA", SubtleUtil.toRsaSsaPkcs1Algo(HashType.SHA512));
    assertThrows(GeneralSecurityException.class, () -> SubtleUtil.toRsaSsaPkcs1Algo(HashType.SHA1));
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
    assertThrows(
        GeneralSecurityException.class, () -> SubtleUtil.putAsUnsigedInt(buffer, 0xFFFFFFFFL + 1L));
  }

  @Test
  public void testPutAsUnsigedInt_minusOne_throws() throws Exception {
    ByteBuffer buffer = ByteBuffer.allocate(4);
    assertThrows(GeneralSecurityException.class, () -> SubtleUtil.putAsUnsigedInt(buffer, -1));
  }

  @Test
  public void bytes2Integer() throws Exception {
    assertThat(SubtleUtil.bytes2Integer(new byte[] {(byte) 0x00}))
        .isEqualTo(BigInteger.ZERO);
    assertThat(SubtleUtil.bytes2Integer(new byte[] {(byte) 0x01}))
        .isEqualTo(BigInteger.ONE);
    assertThat(SubtleUtil.bytes2Integer(new byte[] {(byte) 0x7F}))
        .isEqualTo(BigInteger.valueOf(127));
    // The input should be interpreted as an unsigned integers. So 0x80 is 128.
    assertThat(SubtleUtil.bytes2Integer(new byte[] {(byte) 0x80}))
        .isEqualTo(BigInteger.valueOf(128));
    assertThat(SubtleUtil.bytes2Integer(new byte[] {(byte) 0xFF}))
        .isEqualTo(BigInteger.valueOf(255));
    assertThat(SubtleUtil.bytes2Integer(new byte[] {(byte) 0x01, (byte) 0x00}))
        .isEqualTo(BigInteger.valueOf(256));
    assertThat(SubtleUtil.bytes2Integer(new byte[] {(byte) 0x01, (byte) 0x02}))
        .isEqualTo(BigInteger.valueOf(258));
    // leading zeros are ignored
    assertThat(SubtleUtil.bytes2Integer(
                   new byte[] {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x02}))
        .isEqualTo(BigInteger.valueOf(258));
    // the empty array is decoded to 0.
    assertThat(
        SubtleUtil.bytes2Integer(new byte[] {})).isEqualTo(BigInteger.ZERO);
  }

  @Test
  public void integer2Bytes_success() throws Exception {
    assertThat(SubtleUtil.integer2Bytes(BigInteger.ZERO, /*intendedLength=*/ 0))
        .isEqualTo(new byte[] {});
    assertThat(SubtleUtil.integer2Bytes(BigInteger.ZERO, /*intendedLength=*/ 1))
        .isEqualTo(new byte[] {(byte) 0x00});
    assertThat(SubtleUtil.integer2Bytes(BigInteger.ZERO, /*intendedLength=*/ 2))
        .isEqualTo(new byte[] {(byte) 0x00, (byte) 0x00});
    assertThat(SubtleUtil.integer2Bytes(BigInteger.ONE, /*intendedLength=*/ 1))
        .isEqualTo(new byte[] {(byte) 0x01});
    assertThat(SubtleUtil.integer2Bytes(BigInteger.ONE, /*intendedLength=*/ 2))
        .isEqualTo(new byte[] {(byte) 0x00, (byte) 0x01});
    assertThat(SubtleUtil.integer2Bytes(BigInteger.valueOf(127), /*intendedLength=*/ 1))
        .isEqualTo(new byte[] {(byte) 0x7F});
    assertThat(SubtleUtil.integer2Bytes(BigInteger.valueOf(127), /*intendedLength=*/ 2))
        .isEqualTo(new byte[] {(byte) 0x00, (byte) 0x7F});
    assertThat(SubtleUtil.integer2Bytes(BigInteger.valueOf(127), /*intendedLength=*/ 3))
        .isEqualTo(new byte[] {(byte) 0x00, (byte) 0x00, (byte) 0x7F});
    assertThat(SubtleUtil.integer2Bytes(BigInteger.valueOf(128), /*intendedLength=*/ 1))
        .isEqualTo(new byte[] {(byte) 0x80});
    assertThat(SubtleUtil.integer2Bytes(BigInteger.valueOf(128), /*intendedLength=*/ 2))
        .isEqualTo(new byte[] {(byte) 0x00, (byte) 0x80});
    assertThat(SubtleUtil.integer2Bytes(BigInteger.valueOf(128), /*intendedLength=*/ 3))
        .isEqualTo(new byte[] {(byte) 0x00, (byte) 0x00, (byte) 0x80});
    assertThat(SubtleUtil.integer2Bytes(BigInteger.valueOf(255), /*intendedLength=*/ 1))
        .isEqualTo(new byte[] {(byte) 0xFF});
    assertThat(SubtleUtil.integer2Bytes(BigInteger.valueOf(255), /*intendedLength=*/ 2))
        .isEqualTo(new byte[] {(byte) 0x00, (byte) 0xFF});
    assertThat(SubtleUtil.integer2Bytes(BigInteger.valueOf(255), /*intendedLength=*/ 3))
        .isEqualTo(new byte[] {(byte) 0x00, (byte) 0x00, (byte) 0xFF});
    assertThat(SubtleUtil.integer2Bytes(BigInteger.valueOf(256), /*intendedLength=*/ 2))
        .isEqualTo(new byte[] {(byte) 0x01, (byte) 0x00});
    assertThat(SubtleUtil.integer2Bytes(BigInteger.valueOf(258), /*intendedLength=*/ 2))
        .isEqualTo(new byte[] {(byte) 0x01, (byte) 0x02});
    assertThat(SubtleUtil.integer2Bytes(BigInteger.valueOf(258), /*intendedLength=*/ 4))
        .isEqualTo(new byte[] {(byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x02});
  }

  @Test
  public void integer2Bytes_failWhenIntegerIsNegative() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> SubtleUtil.integer2Bytes(BigInteger.valueOf(-1), /*intendedLength=*/ 2));
    assertThrows(
        IllegalArgumentException.class,
        () -> SubtleUtil.integer2Bytes(BigInteger.valueOf(-42), /*intendedLength=*/ 2));
  }

  @Test
  public void integer2Bytes_failWhenIntegerIsLargerThanIntendedLength() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> SubtleUtil.integer2Bytes(BigInteger.ONE, /* intendedLength= */ 0));
    assertThrows(
        GeneralSecurityException.class,
        () -> SubtleUtil.integer2Bytes(BigInteger.valueOf(256), /*intendedLength=*/ 1));
    assertThrows(
        GeneralSecurityException.class,
        () -> SubtleUtil.integer2Bytes(BigInteger.valueOf(256 * 256), /*intendedLength=*/ 2));
  }

}
