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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for AesCmac */
@RunWith(JUnit4.class)
public class AesCmacTest {

  @Test
  public void voidEncryptionTestVector() throws GeneralSecurityException {
    AesCmac c = new AesCmac(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c"));
    byte[] pt = new byte[0];
    byte[] result = c.computeMac(pt);
    String hex = Hex.encode(result);
    assertEquals("bb1d6929e95937287fa37d129b756746", hex);
  }

  @Test
  public void singleBlockEncryptionTestVector() throws GeneralSecurityException {
    AesCmac c = new AesCmac(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c"));
    byte[] pt = Hex.decode("6bc1bee22e409f96e93d7e117393172a");
    byte[] result = c.computeMac(pt);
    String hex = Hex.encode(result);
    assertEquals("070a16b46b4d4144f79bdd9dd04a287c", hex);
  }

  @Test
  public void twoFullBlocksEncryptionTestVector() throws GeneralSecurityException {
    AesCmac c = new AesCmac(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c"));
    byte[] pt =
        Hex.decode(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                + "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    byte[] result = c.computeMac(pt);
    String hex = Hex.encode(result);
    assertEquals("51f0bebf7e3b9d92fc49741779363cfe", hex);
  }

  @Test
  public void partialBlocksEncryptionTestVector() throws GeneralSecurityException {
    AesCmac c = new AesCmac(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c"));
    byte[] pt =
        Hex.decode(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411");
    byte[] result = c.computeMac(pt);
    String hex = Hex.encode(result);
    assertEquals("dfa66747de9ae63030ca32611497c827", hex);
  }

  @Test
  public void randomMacThenCheck() throws GeneralSecurityException {
    for (int triesKey = 0; triesKey < 100; triesKey++) {
      AesCmac c = new AesCmac(Random.randBytes(16));
      for (int triesPlaintext = 0; triesPlaintext < 100; triesPlaintext++) {
        byte[] plaintext = Random.randBytes(Random.rand(1024) + 1);
        c.verifyMac(c.computeMac(plaintext), plaintext);
      }
    }
  }

  @Test
  public void randomMacThenFlipShouldNotCheck() throws GeneralSecurityException {
    for (int triesKey = 0; triesKey < 100; triesKey++) {
      AesCmac c = new AesCmac(Random.randBytes(16));
      for (int triesPlaintext = 0; triesPlaintext < 100; triesPlaintext++) {
        byte[] plaintext = Random.randBytes(Random.rand(1024) + 1);
        byte[] initialMac = c.computeMac(plaintext);

        // Modify every bit of the tag.
        for (int b = 0; b < initialMac.length; b++) {
          for (int bit = 0; bit < 8; bit++) {
            byte[] modified = Arrays.copyOf(initialMac, initialMac.length);
            modified[b] ^= (byte) (1 << bit);
            try {
              c.verifyMac(plaintext, modified);
              fail("Expected GeneralSecurityException");
            } catch (GeneralSecurityException ex) {
              // expected.
            }
          }
        }
      }
    }
  }
}
