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

package com.google.cloud.crypto.tink.aead;

import static org.junit.Assert.assertArrayEquals;

import java.security.SecureRandom;
import org.junit.Test;

/**
 * Unit tests for AesCtrJceCipher.
 * TODO(quangnguyen): Add more tests.
 */
public class AesCtrJceCipherTest {

  @Test
  public void testEncryptDecrypt() throws Exception {
    SecureRandom rand = new SecureRandom();
    byte[] key = new byte[16];
    rand.nextBytes(key);
    int ivSize = 12;
    AesCtrJceCipher c = new AesCtrJceCipher(key, ivSize);
    byte[] plaintext = "Hello".getBytes("UTF-8");
    byte[] ciphertext = c.encrypt(plaintext);
    assertArrayEquals(plaintext, c.decrypt(ciphertext));
  }
}
