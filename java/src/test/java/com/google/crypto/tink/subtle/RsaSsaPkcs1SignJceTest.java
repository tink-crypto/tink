// Copyright 2018 Google Inc.
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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.subtle.Enums.HashType;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for RsaSsaPkcs1SignJce. */
@RunWith(JUnit4.class)
public class RsaSsaPkcs1SignJceTest {
  @Test
  public void testConstructorExceptions() throws Exception {
    int keySize = 2048;
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(keySize);

    RSAPrivateCrtKey priv = (RSAPrivateCrtKey) keyGen.generateKeyPair().getPrivate();
    try {
      new RsaSsaPkcs1SignJce(priv, HashType.SHA1);
      fail("Unsafe hash, should have thrown exception.");
    } catch (GeneralSecurityException e) {
      // Expected.
      TestUtil.assertExceptionContains(e, "SHA1 is not safe");
    }
  }

  @Test
  public void testBasicAgainstJce() throws Exception {
    int keySize = 2048;
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(keySize);
    KeyPair keyPair = keyGen.generateKeyPair();
    RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateCrtKey priv = (RSAPrivateCrtKey) keyPair.getPrivate();

    // Sign with RsaSsaPkcs1SignJce.
    String message = "Hello";
    RsaSsaPkcs1SignJce signer = new RsaSsaPkcs1SignJce(priv, HashType.SHA256);
    byte[] signature = signer.sign(message.getBytes("UTF-8"));

    // Verify with JCE's Signature.
    Signature verifier = Signature.getInstance("SHA256withRSA");
    verifier.initVerify(pub);
    verifier.update(message.getBytes("UTF-8"));
    assertTrue(verifier.verify(signature));
  }

  @Test
  public void testSignWithTheSameMessage() throws Exception {
    if (TestUtil.isTsan()) {
      // This test times out when running under thread sanitizer, so we just skip.
      return;
    }
    int keySize = 4096;
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(keySize);
    KeyPair keyPair = keyGen.generateKeyPair();
    RSAPrivateCrtKey priv = (RSAPrivateCrtKey) keyPair.getPrivate();
    RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();

    byte[] msg = Random.randBytes(20);
    TreeSet<String> allSignatures = new TreeSet<String>();
    RsaSsaPkcs1SignJce signer = new RsaSsaPkcs1SignJce(priv, HashType.SHA512);
    for (int i = 0; i < 100; i++) {
      byte[] sig = signer.sign(msg);
      allSignatures.add(TestUtil.hexEncode(sig));
      // Verify with JCE's Signature.
      Signature verifier = Signature.getInstance("SHA512WithRSA");
      verifier.initVerify(pub);
      verifier.update(msg);
      if (!verifier.verify(sig)) {
        fail(
            String.format(
                "\n\nMessage: %s\nSignature: %s\nPrivateKey: %s\nPublicKey: %s\n",
                TestUtil.hexEncode(msg),
                TestUtil.hexEncode(sig),
                TestUtil.hexEncode(priv.getEncoded()),
                TestUtil.hexEncode(pub.getEncoded())));
      }
    }
    // RSA SSA PKCS1 is deterministic, expect a unique signature for the same message.
    assertEquals(1, allSignatures.size());
  }
}
