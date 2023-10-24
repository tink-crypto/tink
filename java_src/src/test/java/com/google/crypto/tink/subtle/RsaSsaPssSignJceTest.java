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

import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPssTestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.crypto.tink.testing.TestUtil;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for RsaSsaPssSignJce. */
@RunWith(Theories.class)
public class RsaSsaPssSignJceTest {
  private static final Charset UTF_8 = Charset.forName("UTF-8");

  @Before
  public void useConscrypt() throws Exception {
    // If Tink is build in FIPS-only mode, then we register Conscrypt for the tests.
    if (TinkFips.useOnlyFips()) {
      try {
        Conscrypt.checkAvailability();
        Security.addProvider(Conscrypt.newProvider());
      } catch (Throwable cause) {
        throw new IllegalStateException(
            "Cannot test RSA SSA sign in FIPS-mode without Conscrypt Provider", cause);
      }
    }
  }

  @Test
  public void testConstructorExceptions() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips()); // Only 3072-bit modulus is supported in FIPS.

    if (TestUtil.isTsan()) {
      // This test times out when running under thread sanitizer, so we just skip.
      return;
    }
    int keySize = 2048;
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(keySize);

    RSAPrivateCrtKey priv = (RSAPrivateCrtKey) keyGen.generateKeyPair().getPrivate();
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> new RsaSsaPssSignJce(priv, HashType.SHA1, HashType.SHA1, 20));
    TestUtil.assertExceptionContains(e, "Unsupported hash: SHA1");
  }

  @Test
  public void testBasicAgainstVerifier() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips()); // Only 3072-bit modulus is supported in FIPS.

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
  public void testBasicAgainstVerifierLargerKey() throws Exception {
    if (TestUtil.isTsan()) {
      // This test times out when running under thread sanitizer, so we just skip.
      return;
    }
    int keySize = 3072;
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
    Assume.assumeTrue(!TinkFips.useOnlyFips()); // Only 3072-bit modulus is supported in FIPS.

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

  /**
   * Tests that the verifier can verify a the signature for the message and key in the test vector.
   */
  @Theory
  public void test_validateSignatureInTestVector(
      @FromDataPoints("testVectors") SignatureTestVector testVector) throws Exception {
    RsaSsaPssPrivateKey key = (RsaSsaPssPrivateKey) testVector.getPrivateKey();
    PublicKeyVerify verifier = RsaSsaPssVerifyJce.create(key.getPublicKey());
    verifier.verify(testVector.getSignature(), testVector.getMessage());
  }

  /**
   * Tests that the verifier can verify a newly generated signature for the message and key in the
   * test vector.
   */
  @Theory
  public void test_computeAndValidateFreshSignatureWithTestVector(
      @FromDataPoints("testVectors") SignatureTestVector testVector) throws Exception {
    RsaSsaPssPrivateKey key = (RsaSsaPssPrivateKey) testVector.getPrivateKey();
    PublicKeySign signer = RsaSsaPssSignJce.create(key);
    byte[] signature = signer.sign(testVector.getMessage());
    PublicKeyVerify verifier = RsaSsaPssVerifyJce.create(key.getPublicKey());
    verifier.verify(signature, testVector.getMessage());
  }

  /** Tests that the verification fails for a different message. */
  @Theory
  public void test_computeAndValidate_modifiedMessage_throws(
      @FromDataPoints("testVectors") SignatureTestVector testVector) throws Exception {
    RsaSsaPssPrivateKey key = (RsaSsaPssPrivateKey) testVector.getPrivateKey();
    byte[] modifiedMessage = Bytes.concat(testVector.getMessage(), new byte[] {1});
    PublicKeyVerify verifier = RsaSsaPssVerifyJce.create(key.getPublicKey());
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verify(testVector.getSignature(), modifiedMessage));
  }

  /** Tests that the verification fails if we modify the output prefix. */
  @Theory
  public void test_computeAndValidate_modifiedOutputPrefix_throws(
      @FromDataPoints("testVectors") SignatureTestVector testVector) throws Exception {
    RsaSsaPssPrivateKey key = (RsaSsaPssPrivateKey) testVector.getPrivateKey();
    if (key.getOutputPrefix().size() == 0) {
      return;
    }
    byte[] modifiedSignature = testVector.getSignature();
    modifiedSignature[1] ^= 0x01;
    PublicKeyVerify verifier = RsaSsaPssVerifyJce.create(key.getPublicKey());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            verifier.verify(
                Arrays.copyOf(modifiedSignature, modifiedSignature.length),
                testVector.getMessage()));
  }

  @DataPoints("testVectors")
  public static final SignatureTestVector[] SIGNATURE_TEST_VECTORS =
      RsaSsaPssTestUtil.createRsaPssTestVectors();
}
