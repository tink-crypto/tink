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

import com.google.crypto.tink.WycheproofTestUtil;
import java.security.GeneralSecurityException;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for {@link Ed25519Verify}.
 *
 */
@RunWith(JUnit4.class)
public final class Ed25519VerifyTest {
  @Test
  public void testVerificationWithPublicKeyLengthDifferentFrom32Byte() throws Exception {
    try {
      Ed25519Verify unused = new Ed25519Verify(new byte[31]);
      fail("Public key length should be 32-byte");
    } catch (IllegalArgumentException expected) {
    }
    try {
      Ed25519Verify unused = new Ed25519Verify(new byte[33]);
      fail("Public key length should be 32-byte");
    } catch (IllegalArgumentException expected) {
    }
  }

  private byte[] getMessage(JSONObject testcase) throws Exception {
    if (testcase.has("msg")) {
      return Hex.decode(testcase.getString("msg"));
    } else {
      return Hex.decode(testcase.getString("message"));
    }
  }

  @Test
  public void testVerificationWithWycheproofVectors() throws Exception {
    JSONObject json =
        WycheproofTestUtil.readJson("../wycheproof/testvectors/eddsa_test.json");
    int errors = 0;
    JSONArray testGroups = json.getJSONArray("testGroups");
    for (int i = 0; i < testGroups.length(); i++) {
      JSONObject group = testGroups.getJSONObject(i);
      JSONObject key = group.getJSONObject("key");
      byte[] publicKey = Hex.decode(key.getString("pk"));
      JSONArray tests = group.getJSONArray("tests");
      for (int j = 0; j < tests.length(); j++) {
        JSONObject testcase = tests.getJSONObject(j);
        String tcId =
            String.format(
                "testcase %d (%s)", testcase.getInt("tcId"), testcase.getString("comment"));
        byte[] msg = getMessage(testcase);
        byte[] sig = Hex.decode(testcase.getString("sig"));
        String result = testcase.getString("result");
        Ed25519Verify verifier = new Ed25519Verify(publicKey);
        try {
          verifier.verify(sig, msg);
          if (result.equals("invalid")) {
            System.out.printf("FAIL %s: accepting invalid signature%n", tcId);
            errors++;
          }
        } catch (GeneralSecurityException ex) {
          if (result.equals("valid")) {
            System.out.printf("FAIL %s: rejecting valid signature, exception: %s%n", tcId, ex);
            errors++;
          }
        }
      }
    }
    assertEquals(0, errors);
  }
}
