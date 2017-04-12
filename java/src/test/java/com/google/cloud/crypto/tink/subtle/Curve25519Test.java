// Copyright 2017 Google Inc.
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

package com.google.cloud.crypto.tink.subtle;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.cloud.crypto.tink.TestUtil;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for Curve25519.
 */
@RunWith(JUnit4.class)
public class Curve25519Test {

  /**
   * Tests against the test vectors in Section 5.2 of RFC 7748.
   * https://tools.ietf.org/html/rfc7748
   */
  @Test
  public void testRfcTestVectors() {
    byte[] out = Curve25519.x25519(
        TestUtil.hexDecode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
        TestUtil.hexDecode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"));
    assertEquals(
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        TestUtil.hexEncode(out));

    out = Curve25519.x25519(
        TestUtil.hexDecode("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
        TestUtil.hexDecode("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"));
    assertEquals(
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        TestUtil.hexEncode(out));
  }

  /**
   * Iteration test in Section 5.2 of RFC 7748.
   * https://tools.ietf.org/html/rfc7748
   */
  @Test
  public void testIteration() {
    byte[] k = new byte[32]; k[0] = 9;
    byte[] prevK = k;
    k = Curve25519.x25519(k, prevK);
    assertEquals(
        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
        TestUtil.hexEncode(k));
    for (int i = 0; i < 999; i++) {
      byte[] tmp = k;
      k = Curve25519.x25519(k, prevK);
      prevK = tmp;
    }
    assertEquals(
        "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
        TestUtil.hexEncode(k));
    // Omitting 1M iteration to limit the test runtime.
  }

  /**
   * Tests against the test vectors in Section 6.1 of RFC 7748.
   * https://tools.ietf.org/html/rfc7748
   */
  @Test
  public void testDHTestVectors() {
    byte[] out = Curve25519.x25519PublicFromPrivate(
        TestUtil.hexDecode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
    assertEquals(
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        TestUtil.hexEncode(out));

    out = Curve25519.x25519PublicFromPrivate(
        TestUtil.hexDecode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
    assertEquals(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        TestUtil.hexEncode(out));

    out = Curve25519.x25519(
        TestUtil.hexDecode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
        TestUtil.hexDecode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
    assertEquals(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
        TestUtil.hexEncode(out));

    out = Curve25519.x25519(
        TestUtil.hexDecode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
        TestUtil.hexDecode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    assertEquals(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
        TestUtil.hexEncode(out));
  }

  @Test
  public void testGeneratePrivateKeyReturnsIntentionallyMalformedKeys() {
    byte[] privateKey = Curve25519.generatePrivateKey();
    assertEquals(7, privateKey[0] & 7);
    assertEquals(128, privateKey[31] & 192);
  }

  private static void x25519Helper(int privateKeyLen, int peersPublicValueLen, String errorMsg) {
    byte[] privateKey = new byte[privateKeyLen];
    byte[] base = new byte[peersPublicValueLen]; base[0] = 9;
    try {
      Curve25519.x25519(privateKey, base);
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException expected) {
      assertThat(expected).hasMessageThat().containsMatch(errorMsg);
    }
  }

  @Test
  public void testX25519ThrowsIllegalArgExceptionWhenPrivateKeySizeIsLessThan32Bytes() {
    x25519Helper(31, 32, "Private key must have 32 bytes.");
  }

  @Test
  public void testX25519ThrowsIllegalArgExceptionWhenPrivateKeySizeIsGreaterThan32Bytes() {
    x25519Helper(33, 32, "Private key must have 32 bytes.");
  }

  @Test
  public void testX25519ThrowsIllegalArgExceptionWhenPeersPublicValueIsLessThan32Bytes() {
    x25519Helper(32, 31, "Peer's public key must have 32 bytes.");
  }

  @Test
  public void testX25519ThrowsIllegalArgExceptionWhenPeersPublicValueIsGreaterThan32Bytes() {
    x25519Helper(32, 33, "Peer's public key must have 32 bytes.");
  }

  private static void x25519PublicFromPrivateHelper(int privateKeyLen, String errorMsg) {
    byte[] privateKey = new byte[privateKeyLen];
    try {
      Curve25519.x25519PublicFromPrivate(privateKey);
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException expected) {
      assertThat(expected).hasMessageThat().containsMatch(errorMsg);
    }
  }

  @Test
  public void testX25519PublicFromPrivateThrowsIllegalArgExWhenPrivateKeyIsLessThan32Bytes() {
    x25519PublicFromPrivateHelper(31, "Private key must have 32 bytes.");
  }

  @Test
  public void testX25519PublicFromPrivateThrowsIllegalArgExWhenPrivateKeyIsGreaterThan32Bytes() {
    x25519PublicFromPrivateHelper(33, "Private key must have 32 bytes.");
  }
}
