// Copyright 2021 Google LLC
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

package com.google.crypto.tink.aead.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link ChaCha20Util}. */
@RunWith(JUnit4.class)
public final class ChaCha20UtilTest {
  /** https://tools.ietf.org/html/rfc7539#section-2.1.1 */
  @Test
  public void testQuarterRound() {
    int[] x = TestUtil.twoCompInt(new long[] {0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567});
    ChaCha20Util.quarterRound(x, 0, 1, 2, 3);
    assertThat(x)
        .isEqualTo(
            TestUtil.twoCompInt(new long[] {0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb}));
  }

  /** https://tools.ietf.org/html/rfc7539#section-2.2.1 */
  @Test
  public void testQuarterRound16() {
    int[] x =
        TestUtil.twoCompInt(
            new long[] {
              0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
              0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
              0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
              0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320
            });
    ChaCha20Util.quarterRound(x, 2, 7, 8, 13);
    assertThat(x)
        .isEqualTo(
            TestUtil.twoCompInt(
                new long[] {
                  0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
                  0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
                  0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
                  0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320
                }));
  }

  /** https://datatracker.ietf.org/doc/html/rfc7539#section-2.3.2 */
  @Test
  public void testSetSigmaAndKey() {
    int[] key =
        TestUtil.twoCompInt(
            new long[] {
              0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
              0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c
            });
    int[] state = new int[ChaCha20Util.BLOCK_SIZE_IN_INTS];
    ChaCha20Util.setSigmaAndKey(state, key);
    // Verify that first four words equal ChaCha20Util.SIGMA.
    assertThat(Arrays.copyOf(state, 4))
        .isEqualTo(
            TestUtil.twoCompInt(new long[] {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}));
    // Verify that next eight words equal key.
    assertThat(Arrays.copyOfRange(state, 4, 12)).isEqualTo(key);
  }

  @Test
  public void toIntArrayAndBack_isEqual() {
    byte[] key = Random.randBytes(32);
    assertThat(ChaCha20Util.toByteArray(ChaCha20Util.toIntArray(key))).isEqualTo(key);
    byte[] nonce = Random.randBytes(24);
    assertThat(ChaCha20Util.toByteArray(ChaCha20Util.toIntArray(nonce))).isEqualTo(nonce);
    byte[] empty = new byte[0];
    assertThat(ChaCha20Util.toByteArray(ChaCha20Util.toIntArray(empty))).isEqualTo(empty);
  }

  @Test
  public void toIntArray_lengthNotMutipleOfFour_throws() {
    byte[] data = Random.randBytes(26);
    assertThrows(IllegalArgumentException.class, () -> ChaCha20Util.toIntArray(data));
  }

  private static class HChaCha20TestVector {
    public final int[] key;
    public final int[] in;
    public final int[] out;

    public HChaCha20TestVector(String key, String in, String out) {
      this.key = ChaCha20Util.toIntArray(Hex.decode(key));
      this.in = ChaCha20Util.toIntArray(Hex.decode(in));
      this.out = ChaCha20Util.toIntArray(Hex.decode(out));
    }
  }

  private static final HChaCha20TestVector[] hChaCha20TestVectors = {
    // From libsodium's test/default/xchacha20.c (tv_hchacha20).
    new HChaCha20TestVector(
        "24f11cce8a1b3d61e441561a696c1c1b7e173d084fd4812425435a8896a013dc",
        "d9660c5900ae19ddad28d6e06e45fe5e",
        "5966b3eec3bff1189f831f06afe4d4e3be97fa9235ec8c20d08acfbbb4e851e3"),
    new HChaCha20TestVector(
        "80a5f6272031e18bb9bcd84f3385da65e7731b7039f13f5e3d475364cd4d42f7",
        "c0eccc384b44c88e92c57eb2d5ca4dfa",
        "6ed11741f724009a640a44fce7320954c46e18e0d7ae063bdbc8d7cf372709df"),
    new HChaCha20TestVector(
        "cb1fc686c0eec11a89438b6f4013bf110e7171dace3297f3a657a309b3199629",
        "fcd49b93e5f8f299227e64d40dc864a3",
        "84b7e96937a1a0a406bb7162eeaad34308d49de60fd2f7ec9dc6a79cbab2ca34"),
    new HChaCha20TestVector(
        "6640f4d80af5496ca1bc2cfff1fefbe99638dbceaabd7d0ade118999d45f053d",
        "31f59ceeeafdbfe8cae7914caeba90d6",
        "9af4697d2f5574a44834a2c2ae1a0505af9f5d869dbe381a994a18eb374c36a0"),
    new HChaCha20TestVector(
        "0693ff36d971225a44ac92c092c60b399e672e4cc5aafd5e31426f123787ac27",
        "3a6293da061da405db45be1731d5fc4d",
        "f87b38609142c01095bfc425573bb3c698f9ae866b7e4216840b9c4caf3b0865"),
    new HChaCha20TestVector(
        "809539bd2639a23bf83578700f055f313561c7785a4a19fc9114086915eee551",
        "780c65d6a3318e479c02141d3f0b3918",
        "902ea8ce4680c09395ce71874d242f84274243a156938aaa2dd37ac5be382b42"),
    new HChaCha20TestVector(
        "1a170ddf25a4fd69b648926e6d794e73408805835c64b2c70efddd8cd1c56ce0",
        "05dbee10de87eb0c5acb2b66ebbe67d3",
        "a4e20b634c77d7db908d387b48ec2b370059db916e8ea7716dc07238532d5981"),
    new HChaCha20TestVector(
        "3b354e4bb69b5b4a1126f509e84cad49f18c9f5f29f0be0c821316a6986e15a6",
        "d8a89af02f4b8b2901d8321796388b6c",
        "9816cb1a5b61993735a4b161b51ed2265b696e7ded5309c229a5a99f53534fbc"),
    new HChaCha20TestVector(
        "4b9a818892e15a530db50dd2832e95ee192e5ed6afffb408bd624a0c4e12a081",
        "a9079c551de70501be0286d1bc78b045",
        "ebc5224cf41ea97473683b6c2f38a084bf6e1feaaeff62676db59d5b719d999b"),
    new HChaCha20TestVector(
        "c49758f00003714c38f1d4972bde57ee8271f543b91e07ebce56b554eb7fa6a7",
        "31f0204e10cf4f2035f9e62bb5ba7303",
        "0dd8cc400f702d2c06ed920be52048a287076b86480ae273c6d568a2e9e7518c"),
    // From https://tools.ietf.org/html/draft-arciszewski-xchacha-01#section-2.2.1.
    new HChaCha20TestVector(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "000000090000004a0000000031415927",
        "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
  };

  @Test
  public void testHChaCha20TestVectors() {
    for (HChaCha20TestVector test : hChaCha20TestVectors) {
      int[] output = ChaCha20Util.hChaCha20(test.key, test.in);
      assertThat(output).isEqualTo(test.out);
    }
  }

  // https://tools.ietf.org/html/draft-arciszewski-xchacha-01#section-2.2.1
  @Test
  public void hChaCha20_testVector() {
    byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    byte[] nonce = Hex.decode("000000090000004a0000000031415927");
    byte[] expected =
        Hex.decode("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
    assertThat(ChaCha20Util.hChaCha20(key, nonce)).isEqualTo(expected);
  }
}
