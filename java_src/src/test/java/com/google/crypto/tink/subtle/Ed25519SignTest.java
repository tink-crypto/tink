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
import static org.junit.Assert.fail;

import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.util.TreeSet;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for {@link Ed25519Sign}.
 *
 */
@RunWith(JUnit4.class)
public final class Ed25519SignTest {

  @Test
  public void testSigningOneKeyWithMultipleMessages() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    Ed25519Sign.KeyPair keyPair = Ed25519Sign.KeyPair.newKeyPair();
    Ed25519Sign signer = new Ed25519Sign(keyPair.getPrivateKey());
    Ed25519Verify verifier = new Ed25519Verify(keyPair.getPublicKey());
    for (int i = 0; i < 100; i++) {
      byte[] msg = Random.randBytes(20);
      byte[] sig = signer.sign(msg);
      try {
        verifier.verify(sig, msg);
      } catch (GeneralSecurityException ex) {
        fail(
            String.format(
                "\n\nMessage: %s\nSignature: %s\nPrivateKey: %s\nPublicKey: %s\n",
                TestUtil.hexEncode(msg),
                TestUtil.hexEncode(sig),
                TestUtil.hexEncode(keyPair.getPrivateKey()),
                TestUtil.hexEncode(keyPair.getPublicKey())));
      }
    }
  }

  @Test
  public void testSigningOneKeyWithTheSameMessage() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    Ed25519Sign.KeyPair keyPair = Ed25519Sign.KeyPair.newKeyPair();
    Ed25519Sign signer = new Ed25519Sign(keyPair.getPrivateKey());
    Ed25519Verify verifier = new Ed25519Verify(keyPair.getPublicKey());
    byte[] msg = Random.randBytes(20);
    TreeSet<String> allSignatures = new TreeSet<String>();
    for (int i = 0; i < 100; i++) {
      byte[] sig = signer.sign(msg);
      allSignatures.add(TestUtil.hexEncode(sig));
      try {
        verifier.verify(sig, msg);
      } catch (GeneralSecurityException ex) {
        fail(
            String.format(
                "\n\nMessage: %s\nSignature: %s\nPrivateKey: %s\nPublicKey: %s\n",
                TestUtil.hexEncode(msg),
                TestUtil.hexEncode(sig),
                TestUtil.hexEncode(keyPair.getPrivateKey()),
                TestUtil.hexEncode(keyPair.getPublicKey())));
      }
    }
    // Ed25519 is deterministic, expect a unique signature for the same message.
    assertEquals(1, allSignatures.size());
  }

  @Test
  public void testSignWithPrivateKeyLengthDifferentFrom32Byte() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          Ed25519Sign unused = new Ed25519Sign(new byte[31]);
        });
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          Ed25519Sign unused = new Ed25519Sign(new byte[33]);
        });
  }

  @Test
  public void testSigningWithMultipleRandomKeysAndMessages() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    for (int i = 0; i < 100; i++) {
      Ed25519Sign.KeyPair keyPair = Ed25519Sign.KeyPair.newKeyPair();
      Ed25519Sign signer = new Ed25519Sign(keyPair.getPrivateKey());
      Ed25519Verify verifier = new Ed25519Verify(keyPair.getPublicKey());
      byte[] msg = Random.randBytes(20);
      byte[] sig = signer.sign(msg);
      try {
        verifier.verify(sig, msg);
      } catch (GeneralSecurityException ex) {
        fail(
            String.format(
                "\n\nMessage: %s\nSignature: %s\nPrivateKey: %s\nPublicKey: %s\n",
                TestUtil.hexEncode(msg),
                TestUtil.hexEncode(sig),
                TestUtil.hexEncode(keyPair.getPrivateKey()),
                TestUtil.hexEncode(keyPair.getPublicKey())));
      }
    }
  }

  private byte[] getMessage(JsonObject testcase) throws Exception {
    if (testcase.has("msg")) {
      return Hex.decode(testcase.get("msg").getAsString());
    } else {
      return Hex.decode(testcase.get("message").getAsString());
    }
  }

  @Test
  public void testSigningWithWycheproofVectors() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    JsonObject json =
        WycheproofTestUtil.readJson("../wycheproof/testvectors/eddsa_test.json");
    int errors = 0;
    JsonArray testGroups = json.get("testGroups").getAsJsonArray();
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      JsonObject key = group.get("key").getAsJsonObject();
      byte[] privateKey = Hex.decode(key.get("sk").getAsString());
      JsonArray tests = group.get("tests").getAsJsonArray();
      for (int j = 0; j < tests.size(); j++) {
        JsonObject testcase = tests.get(j).getAsJsonObject();
        String tcId =
            String.format(
                "testcase %d (%s)",
                testcase.get("tcId").getAsInt(), testcase.get("comment").getAsString());
        byte[] msg = getMessage(testcase);
        byte[] sig = Hex.decode(testcase.get("sig").getAsString());
        String result = testcase.get("result").getAsString();
        if (result.equals("invalid")) {
          continue;
        }
        Ed25519Sign signer = new Ed25519Sign(privateKey);
        byte[] computedSig = signer.sign(msg);
        assertArrayEquals(tcId, sig, computedSig);
      }
    }
    assertEquals(0, errors);
  }

  @Test
  public void testKeyPairFromSeedTooShort() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] keyMaterial = Random.randBytes(10);
    assertThrows(
        IllegalArgumentException.class, () -> Ed25519Sign.KeyPair.newKeyPairFromSeed(keyMaterial));
  }

  @Test
  public void testFailIfFipsModuleNotAvailable() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());

    byte[] key = Random.randBytes(32);
    assertThrows(GeneralSecurityException.class, () -> new Ed25519Sign(key));
  }
}
