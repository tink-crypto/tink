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

package com.google.crypto.tink.subtle;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Mac;
import com.google.crypto.tink.config.TinkFips;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link AesCmac}. */
@RunWith(JUnit4.class)
public class PrfAesCmacTest {
  private static class MacTestVector {
    String algName;
    public byte[] key;
    public byte[] message;
    public byte[] tag;

    public MacTestVector(String algName, String key, String message, String tag) {
      this.algName = algName;
      this.key = Hex.decode(key);
      this.message = Hex.decode(message);
      this.tag = Hex.decode(tag);
    }
  }

  // Test data from https://tools.ietf.org/html/rfc4493#section-4.
  private static final MacTestVector[] CMAC_TEST_VECTORS = {
    new MacTestVector(
        "AESCMAC", "2b7e151628aed2a6abf7158809cf4f3c", "", "bb1d6929e95937287fa37d129b756746"),
    new MacTestVector(
        "AESCMAC",
        "2b7e151628aed2a6abf7158809cf4f3c",
        "6bc1bee22e409f96e93d7e117393172a"
            + "ae2d8a571e03ac9c9eb76fac45af8e51"
            + "30c81c46a35ce411",
        "dfa66747de9ae63030ca32611497c827"),
    new MacTestVector(
        "AESCMAC",
        "2b7e151628aed2a6abf7158809cf4f3c",
        "6bc1bee22e409f96e93d7e117393172a"
            + "ae2d8a571e03ac9c9eb76fac45af8e51"
            + "30c81c46a35ce411e5fbc1191a0a52ef"
            + "f69f2445df4f9b17ad2b417be66c3710",
        "51f0bebf7e3b9d92fc49741779363cfe"),
  };

  @Test
  public void testFipsCompatibility() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());

    // In FIPS-mode we expect that creating a PrfAesCmac fails.
    assertThrows(
        GeneralSecurityException.class,
        () -> new PrfMac(new PrfAesCmac(CMAC_TEST_VECTORS[0].key), 16));
  }

  @Test
  public void testMacTestVectors() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());
    for (MacTestVector t : CMAC_TEST_VECTORS) {
      Mac mac = new PrfMac(new PrfAesCmac(t.key), t.tag.length);
      assertArrayEquals(t.tag, mac.computeMac(t.message));
      try {
        mac.verifyMac(t.tag, t.message);
      } catch (GeneralSecurityException e) {
        throw new AssertionError("Valid MAC, should not throw exception", e);
      }
    }
  }

  @Test
  public void testTagTruncation() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());
    for (MacTestVector t : CMAC_TEST_VECTORS) {
      Mac mac = new PrfMac(new PrfAesCmac(t.key), t.tag.length);
      for (int j = 1; j < t.tag.length; j++) {
        byte[] modifiedTag = Arrays.copyOf(t.tag, t.tag.length - j);
        assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(modifiedTag, t.message));
      }
    }
    // Test with random keys.
    for (MacTestVector t : CMAC_TEST_VECTORS) {
      Mac mac = new PrfMac(new PrfAesCmac(Random.randBytes(t.key.length)), t.tag.length);
      for (int j = 1; j < t.tag.length; j++) {
        byte[] modifiedTag = Arrays.copyOf(t.tag, t.tag.length - j);
        assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(modifiedTag, t.message));
      }
    }
  }

  @Test
  public void testBitFlipMessage() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());
    for (MacTestVector t : CMAC_TEST_VECTORS) {
      Mac mac = new PrfMac(new PrfAesCmac(t.key), t.tag.length);
      for (int b = 0; b < t.message.length; b++) {
        for (int bit = 0; bit < 8; bit++) {
          byte[] modifiedMessage = Arrays.copyOf(t.message, t.message.length);
          modifiedMessage[b] = (byte) (modifiedMessage[b] ^ (1 << bit));
          assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(t.tag, modifiedMessage));
        }
      }
    }
    // Test with random keys.
    for (MacTestVector t : CMAC_TEST_VECTORS) {
      Mac mac = new PrfMac(new PrfAesCmac(Random.randBytes(t.key.length)), t.tag.length);
      for (int b = 0; b < t.message.length; b++) {
        for (int bit = 0; bit < 8; bit++) {
          byte[] modifiedMessage = Arrays.copyOf(t.message, t.message.length);
          modifiedMessage[b] = (byte) (modifiedMessage[b] ^ (1 << bit));
          assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(t.tag, modifiedMessage));
        }
      }
    }
  }

  @Test
  public void testBitFlipTag() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());
    for (MacTestVector t : CMAC_TEST_VECTORS) {
      Mac mac = new PrfMac(new PrfAesCmac(t.key), t.tag.length);
      for (int b = 0; b < t.tag.length; b++) {
        for (int bit = 0; bit < 8; bit++) {
          byte[] modifiedTag = Arrays.copyOf(t.tag, t.tag.length);
          modifiedTag[b] = (byte) (modifiedTag[b] ^ (1 << bit));
          assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(modifiedTag, t.message));
        }
      }
    }
    // Test with random keys.
    for (MacTestVector t : CMAC_TEST_VECTORS) {
      Mac mac = new PrfMac(new PrfAesCmac(Random.randBytes(t.key.length)), t.tag.length);
      for (int b = 0; b < t.tag.length; b++) {
        for (int bit = 0; bit < 8; bit++) {
          byte[] modifiedTag = Arrays.copyOf(t.tag, t.tag.length);
          modifiedTag[b] = (byte) (modifiedTag[b] ^ (1 << bit));
          assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(modifiedTag, t.message));
        }
      }
    }
  }

  @Test
  public void testThrowExceptionIfTagSizeIsTooSmall() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());
    for (int i = 0; i < PrfMac.MIN_TAG_SIZE_IN_BYTES; i++) {
      final int j = i;
      assertThrows(
          InvalidAlgorithmParameterException.class,
          () -> new PrfMac(new PrfAesCmac(Random.randBytes(16)), j));
    }
  }

  @Test
  public void testThrowExceptionIfTagSizeIsTooLarge() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> new PrfMac(new PrfAesCmac(Random.randBytes(16)), 17));
  }
}
