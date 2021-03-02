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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyWrap;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Kwp}. */
@RunWith(JUnit4.class)
public class KwpTest {

  @Test
  public void testWrapUnwrapMsgSizes() throws Exception {
    byte[] wrapKey = Random.randBytes(16);
    KeyWrap wrapper = new Kwp(wrapKey);
    for (int wrappedSize = 16; wrappedSize < 128; wrappedSize++) {
      byte[] keyMaterialToWrap = Random.randBytes(wrappedSize);
      byte[] wrapped = wrapper.wrap(keyMaterialToWrap);
      byte[] unwrapped = wrapper.unwrap(wrapped);
      assertArrayEquals(keyMaterialToWrap, unwrapped);
    }
  }

  @Test
  public void testInvalidKeySizes() throws Exception {
    // Tests the wrapping key. Its key size is either 16 or 32.
    for (int j = 0; j < 255; j++) {
      final int i = j;
      if (i == 16 || i == 32) {
        continue;
      }
      assertThrows(
          GeneralSecurityException.class,
          () -> {
            KeyWrap unused = new Kwp(new byte[i]);
          });
    }
  }

  @Test
  public void testInvalidWrappingSizes() throws Exception {
    byte[] wrapKey = Random.randBytes(16);
    KeyWrap wrapper = new Kwp(wrapKey);
    for (int i = 0; i < 16; i++) {
      final int wrappedSize = i;
      assertThrows(GeneralSecurityException.class, () -> wrapper.wrap(new byte[wrappedSize]));
    }
  }

  @Test
  public void testWycheproof() throws Exception {
    final String expectedVersion = "0.6";
    JsonObject json =
        WycheproofTestUtil.readJson("../wycheproof/testvectors/kwp_test.json");
    Set<String> exceptions = new TreeSet<String>();
    String generatorVersion = json.get("generatorVersion").getAsString();
    if (!generatorVersion.equals(expectedVersion)) {
      System.out.printf("Expecting test vectors with version %s found version %s.\n",
                        expectedVersion, generatorVersion);
    }
    int errors = 0;
    JsonArray testGroups = json.getAsJsonArray("testGroups");
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      JsonArray tests = group.getAsJsonArray("tests");
      for (int j = 0; j < tests.size(); j++) {
        JsonObject testcase = tests.get(j).getAsJsonObject();
        int tcid = testcase.get("tcId").getAsInt();
        String tc = "tcId: " + tcid + " " + testcase.get("comment").getAsString();
        byte[] key = Hex.decode(testcase.get("key").getAsString());
        byte[] data = Hex.decode(testcase.get("msg").getAsString());
        byte[] expected = Hex.decode(testcase.get("ct").getAsString());
        // Result is one of "valid", "invalid", "acceptable".
        // "valid" are test vectors with matching plaintext, ciphertext and tag.
        // "invalid" are test vectors with invalid parameters or invalid ciphertext and tag.
        // "acceptable" are test vectors with weak parameters or legacy formats.
        String result = testcase.get("result").getAsString();

        // Test wrapping
        KeyWrap wrapper;
        try {
          wrapper = new Kwp(key);
        } catch (GeneralSecurityException ex) {
          // tink restrict the key sizes to 128 or 256 bits.
          if (key.length == 16 || key.length == 32) {
            System.out.printf("Rejected valid key:%s\n", tc);
            System.out.println(ex.toString());
            errors++;
          }
          continue;
        }
        try {
          byte[] wrapped = wrapper.wrap(data);
          boolean eq = TestUtil.arrayEquals(expected, wrapped);
          if (result.equals("invalid")) {
            if (eq) {
              // Some test vectors use invalid parameters that should be rejected.
              System.out.printf("Wrapped test case:%s\n", tc);
              errors++;
            }
          } else {
            if (!eq) {
              System.out.printf("Incorrect wrapping for test case:%s wrapped bytes:%s\n",
                                tc, Hex.encode(wrapped));
              errors++;
            }
          }
        } catch (GeneralSecurityException ex) {
          if (result.equals("valid")) {
            System.out.printf("Failed to wrap test case:%s\n", tc);
            errors++;
          }
        } catch (Exception ex) {
          // Other exceptions are violating the interface.
          System.out.printf("Test case %s throws %s.\n", tc, ex);
          errors++;
        }

        // Test unwrapping
        // The algorithms tested in this class are typically malleable. Hence, it is in possible
        // that modifying ciphertext randomly results in some other valid ciphertext.
        // However, all the test vectors in Wycheproof are constructed such that they have
        // invalid padding. If this changes then the test below is too strict.
        try {
          byte[] unwrapped = wrapper.unwrap(expected);
          boolean eq = TestUtil.arrayEquals(data, unwrapped);
          if (result.equals("invalid")) {
            System.out.printf("Unwrapped invalid test case:%s unwrapped:%s\n", tc,
                              Hex.encode(unwrapped));
            errors++;
          } else {
            if (!eq) {
              System.out.printf("Incorrect unwrap. Excepted:%s actual:%s\n",
                                Hex.encode(data), Hex.encode(unwrapped));
              errors++;
            }
          }
        } catch (GeneralSecurityException ex) {
          // Trying to unwrap an invalid key should always result in a GeneralSecurityException
          // or a subclass of it.
          exceptions.add(ex.toString());
          if (result.equals("valid")) {
            System.out.printf("Failed to unwrap:%s\n", tc);
            errors++;
          }
        } catch (Exception ex) {
          // Other exceptions indicate a programming error.
          System.out.printf("Test case:%s throws %s\n", tc, ex);
          exceptions.add(ex.toString());
          errors++;
        }
      }
    }
    // Even though strong pseudorandomness implies that information about incorrectly formatted
    // ciphertexts is not helpful to an attacker, we still don't want to do this and expect
    // exceptions that do not carry information about the unwrapped data.
    System.out.printf("Number of distinct exceptions:%d\n", exceptions.size());
    for (String ex : exceptions) {
      System.out.println(ex);
    }
    assertEquals(0, errors);
  }
}
