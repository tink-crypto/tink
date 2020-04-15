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
import static org.junit.Assert.fail;

import com.google.crypto.tink.Mac;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link AesCmac}. */
@RunWith(JUnit4.class)
public class AesCmacTest {
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
  public void testMacTestVectors() throws Exception {
    for (MacTestVector t : CMAC_TEST_VECTORS) {
      Mac mac = new AesCmac(t.key, t.tag.length);
      assertArrayEquals(t.tag, mac.computeMac(t.message));
      try {
        mac.verifyMac(t.tag, t.message);
      } catch (GeneralSecurityException e) {
        fail("Valid MAC, should not throw exception");
      }
    }
  }

  @Test
  public void testTagTruncation() throws Exception {
    for (MacTestVector t : CMAC_TEST_VECTORS) {
      Mac mac = new AesCmac(t.key, t.tag.length);
      for (int j = 1; j < t.tag.length; j++) {
        byte[] modifiedTag = Arrays.copyOf(t.tag, t.tag.length - j);
        try {
          mac.verifyMac(modifiedTag, t.message);
          fail("Invalid MAC, should have thrown exception");
        } catch (GeneralSecurityException expected) {
          // Expected
        }
      }
    }
    // Test with random keys.
    for (MacTestVector t : CMAC_TEST_VECTORS) {
      Mac mac = new AesCmac(Random.randBytes(t.key.length), t.tag.length);
      for (int j = 1; j < t.tag.length; j++) {
        byte[] modifiedTag = Arrays.copyOf(t.tag, t.tag.length - j);
        try {
          mac.verifyMac(modifiedTag, t.message);
          fail("Invalid MAC, should have thrown exception");
        } catch (GeneralSecurityException expected) {
          // Expected
        }
      }
    }
  }

  @Test
  public void testBitFlipMessage() throws Exception {
    for (MacTestVector t : CMAC_TEST_VECTORS) {
      Mac mac = new AesCmac(t.key, t.tag.length);
      for (int b = 0; b < t.message.length; b++) {
        for (int bit = 0; bit < 8; bit++) {
          byte[] modifiedMessage = Arrays.copyOf(t.message, t.message.length);
          modifiedMessage[b] = (byte) (modifiedMessage[b] ^ (1 << bit));
          try {
            mac.verifyMac(t.tag, modifiedMessage);
            fail("Invalid MAC, should have thrown exception");
          } catch (GeneralSecurityException expected) {
            // Expected
          }
        }
      }
    }
    // Test with random keys.
    for (MacTestVector t : CMAC_TEST_VECTORS) {
      Mac mac = new AesCmac(Random.randBytes(t.key.length), t.tag.length);
      for (int j = 1; j < t.tag.length; j++) {
        byte[] modifiedTag = Arrays.copyOf(t.tag, t.tag.length - j);
        try {
          mac.verifyMac(modifiedTag, t.message);
          fail("Invalid MAC, should have thrown exception");
        } catch (GeneralSecurityException expected) {
          // Expected
        }
      }
    }
  }

  @Test
  public void testBitFlipTag() throws Exception {
    for (MacTestVector t : CMAC_TEST_VECTORS) {
      Mac mac = new AesCmac(t.key, t.tag.length);
      for (int b = 0; b < t.tag.length; b++) {
        for (int bit = 0; bit < 8; bit++) {
          byte[] modifiedTag = Arrays.copyOf(t.tag, t.tag.length);
          modifiedTag[b] = (byte) (modifiedTag[b] ^ (1 << bit));
          try {
            mac.verifyMac(modifiedTag, t.message);
            fail("Invalid MAC, should have thrown exception");
          } catch (GeneralSecurityException expected) {
            // Expected
          }
        }
      }
    }
    // Test with random keys.
    for (MacTestVector t : CMAC_TEST_VECTORS) {
      Mac mac = new AesCmac(Random.randBytes(t.key.length), t.tag.length);
      for (int b = 0; b < t.tag.length; b++) {
        for (int bit = 0; bit < 8; bit++) {
          byte[] modifiedTag = Arrays.copyOf(t.tag, t.tag.length);
          modifiedTag[b] = (byte) (modifiedTag[b] ^ (1 << bit));
          try {
            mac.verifyMac(modifiedTag, t.message);
            fail("Invalid MAC, should have thrown exception");
          } catch (GeneralSecurityException expected) {
            // Expected
          }
        }
      }
    }
  }

  @Test
  public void testThrowExceptionIfTagSizeIsTooSmall() throws Exception {
    for (int i = 0; i < AesCmac.MIN_TAG_SIZE_IN_BYTES; i++) {
      try {
        new AesCmac(Random.randBytes(16), i);
        fail("Expected InvalidAlgorithmParameterException");
      } catch (InvalidAlgorithmParameterException ex) {
        // expected.
      }
    }
  }

  @Test
  public void testThrowExceptionIfTagSizeIsTooLarge() throws Exception {
    try {
      new AesCmac(Random.randBytes(16), 17);
      fail("Expected InvalidAlgorithmParameterException");
    } catch (InvalidAlgorithmParameterException ex) {
      // expected.
    }
  }
}
