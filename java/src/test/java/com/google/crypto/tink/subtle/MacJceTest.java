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
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for MacJce. */
@RunWith(JUnit4.class)
public class MacJceTest {
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

  // Test data from http://csrc.nist.gov/groups/STM/cavp/message-authentication.html#testing.
  private static final MacTestVector[] HMAC_TEST_VECTORS = {
    new MacTestVector(
        "HMACSHA1",
        "816aa4c3ee066310ac1e6666cf830c375355c3c8ba18cfe1f50a48c988b46272",
        "220248f5e6d7a49335b3f91374f18bb8b0ff5e8b9a5853f3cfb293855d78301d837a0a2eb9e4f056f06c08361"
            + "bd07180ee802651e69726c28910d2baef379606815dcbab01d0dc7acb0ba8e65a2928130da0522f2b2b3d05260"
            + "885cf1c64f14ca3145313c685b0274bf6a1cb38e4f99895c6a8cc72fbe0e52c01766fede78a1a",
        "17cb2e9e98b748b5ae0f7078ea5519e5"),
    new MacTestVector(
        "HMACSHA256",
        "6f35628d65813435534b5d67fbdb54cb33403d04e843103e6399f806cb5df95febbdd61236f33245",
        "752cff52e4b90768558e5369e75d97c69643509a5e5904e0a386cbe4d0970ef73f918f675945a9aefe26daea27"
            + "587e8dc909dd56fd0468805f834039b345f855cfe19c44b55af241fff3ffcd8045cd5c288e6c4e284c3720570b"
            + "58e4d47b8feeedc52fd1401f698a209fccfa3b4c0d9a797b046a2759f82a54c41ccd7b5f592b",
        "05d1243e6465ed9620c9aec1c351a186"),
    new MacTestVector(
        "HMACSHA512",
        "726374c4b8df517510db9159b730f93431e0cd468d4f3821eab0edb93abd0fba46ab4f1ef35d54fec3d85fa89e"
            + "f72ff3d35f22cf5ab69e205c10afcdf4aaf11338dbb12073474fddb556e60b8ee52f91163ba314303ee0c910e6"
            + "4e87fbf302214edbe3f2",
        "ac939659dc5f668c9969c0530422e3417a462c8b665e8db25a883a625f7aa59b89c5ad0ece5712ca17442d1798"
            + "c6dea25d82c5db260cb59c75ae650be56569c1bd2d612cc57e71315917f116bbfa65a0aeb8af7840ee83d3e710"
            + "1c52cf652d2773531b7a6bdd690b846a741816c860819270522a5b0cdfa1d736c501c583d916",
        "bd3d2df6f9d284b421a43e5f9cb94bc4ff88a88243f1f0133bad0fb1791f6569"),
  };

  @Test
  public void testMacTestVectors() throws Exception {
    for (MacTestVector t : HMAC_TEST_VECTORS) {
      Mac mac = new MacJce(t.algName, new SecretKeySpec(t.key, "HMAC"), t.tag.length);
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
    for (MacTestVector t : HMAC_TEST_VECTORS) {
      Mac mac = new MacJce(t.algName, new SecretKeySpec(t.key, "HMAC"), t.tag.length);
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
    for (MacTestVector t : HMAC_TEST_VECTORS) {
      Mac mac = new MacJce(
          t.algName, new SecretKeySpec(Random.randBytes(t.key.length), "HMAC"), t.tag.length);
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
    for (MacTestVector t : HMAC_TEST_VECTORS) {
      Mac mac = new MacJce(t.algName, new SecretKeySpec(t.key, "HMAC"), t.tag.length);
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
    for (MacTestVector t : HMAC_TEST_VECTORS) {
      Mac mac = new MacJce(
          t.algName, new SecretKeySpec(Random.randBytes(t.key.length), "HMAC"), t.tag.length);
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
    for (MacTestVector t : HMAC_TEST_VECTORS) {
      Mac mac = new MacJce(t.algName, new SecretKeySpec(t.key, "HMAC"), t.tag.length);
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
    for (MacTestVector t : HMAC_TEST_VECTORS) {
      Mac mac = new MacJce(
          t.algName, new SecretKeySpec(Random.randBytes(t.key.length), "HMAC"), t.tag.length);
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
  public void testThrowExceptionIfKeySizeIsTooSmall() throws Exception {
    try {
      new MacJce("HMACSHA1", new SecretKeySpec(Random.randBytes(15), "HMAC"), 16);
      fail("Expected InvalidAlgorithmParameterException");
    } catch (InvalidAlgorithmParameterException ex) {
      // expected.
    }
  }

  @Test
  public void testThrowExceptionIfTagSizeIsTooSmall() throws Exception {
    testThrowExceptionIfTagSizeIsTooSmall("HMACSHA1");
    testThrowExceptionIfTagSizeIsTooSmall("HMACSHA256");
    testThrowExceptionIfTagSizeIsTooSmall("HMACSHA512");
  }

  private static void testThrowExceptionIfTagSizeIsTooSmall(String algoName) throws Exception {
    for (int i = 0; i < MacJce.MIN_TAG_SIZE_IN_BYTES; i++) {
      try {
        new MacJce(algoName, new SecretKeySpec(Random.randBytes(16), "HMAC"), i);
        fail("Expected InvalidAlgorithmParameterException");
      } catch (InvalidAlgorithmParameterException ex) {
        // expected.
      }
    }
  }

  @Test
  public void testThrowExceptionIfTagSizeIsTooLarge() throws Exception {
    testThrowExceptionIfTagSizeIsTooLarge("HMACSHA1", 21);
    testThrowExceptionIfTagSizeIsTooLarge("HMACSHA256", 33);
    testThrowExceptionIfTagSizeIsTooLarge("HMACSHA512", 65);
  }

  private static void testThrowExceptionIfTagSizeIsTooLarge(String algoName, int tagSize)
      throws Exception {
    try {
      new MacJce(algoName, new SecretKeySpec(Random.randBytes(16), "HMAC"), tagSize);
      fail("Expected InvalidAlgorithmParameterException");
    } catch (InvalidAlgorithmParameterException ex) {
      // expected.
    }
  }
}
