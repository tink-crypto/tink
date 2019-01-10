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

import static org.junit.Assert.fail;

import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.subtle.Enums.HashType;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for RsaSsaPssSignJce. */
@RunWith(JUnit4.class)
public class RsaSsaPssSignJceTest {
  private static final Charset UTF_8 = Charset.forName("UTF-8");

  @Test
  public void testConstructorExceptions() throws Exception {
    int keySize = 2048;
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(keySize);

    RSAPrivateCrtKey priv = (RSAPrivateCrtKey) keyGen.generateKeyPair().getPrivate();
    try {
      new RsaSsaPssSignJce(priv, HashType.SHA1, HashType.SHA1, 20);
      fail("Unsafe hash, should have thrown exception.");
    } catch (GeneralSecurityException e) {
      // Expected.
      TestUtil.assertExceptionContains(e, "SHA1 is not safe");
    }
  }

  @Test
  public void testBasicAgainstVerifier() throws Exception {
    if (TestUtil.isTsan()) {
      // This test times out when running under thread sanitizer, so we just skip.
      return;
    }
    int keySize = 2048;
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(keySize);
    KeyPair keyPair = keyGen.generateKeyPair();
    RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateCrtKey priv = (RSAPrivateCrtKey) keyPair.getPrivate();

    // Sign with RsaSsaPssSignJce.
    byte[] message = "Hello".getBytes(UTF_8);
    RsaSsaPssSignJce signer = new RsaSsaPssSignJce(priv, HashType.SHA256, HashType.SHA256, 32);

    for (int i = 0; i < 1024; i++) {
      byte[] signature = signer.sign(message);
      // Verify with JCE's Signature.
      RsaSsaPssVerifyJce verifier =
          new RsaSsaPssVerifyJce(pub, HashType.SHA256, HashType.SHA256, 32);
      try {
        verifier.verify(signature, message);
      } catch (GeneralSecurityException e) {
        throw new AssertionError("Valid signature, shouldn't throw exception", e);
      }
    }
  }

  @Test
  public void testZeroSaltLength() throws Exception {
    int keySize = 2048;
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(keySize);
    KeyPair keyPair = keyGen.generateKeyPair();
    RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateCrtKey priv = (RSAPrivateCrtKey) keyPair.getPrivate();

    // Sign with RsaSsaPssSignJce.
    byte[] message = "Hello".getBytes(UTF_8);
    RsaSsaPssSignJce signer = new RsaSsaPssSignJce(priv, HashType.SHA256, HashType.SHA256, 0);

    byte[] signature = signer.sign(message);
    // Verify with JCE's Signature.
    RsaSsaPssVerifyJce verifier = new RsaSsaPssVerifyJce(pub, HashType.SHA256, HashType.SHA256, 0);
    try {
      verifier.verify(signature, message);
    } catch (GeneralSecurityException e) {
      throw new AssertionError("Valid signature, shouldn't throw exception", e);
    }
  }
}
