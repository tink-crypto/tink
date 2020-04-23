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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.subtle.EllipticCurves.EcdsaEncoding;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.crypto.tink.testing.TestUtil;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Test for thread safety of {@code Signature}-primitives. This test covers signers.
 *
 * <p>If possible then this unit test should be run using a thread sanitizer. Otherwise only race
 * conditions that actually happend during the test will be detected.
 */
@RunWith(JUnit4.class)
public class SignatureThreadSafetyTest {

  /**
   * Exception handler for uncaught exceptions in a thread.
   *
   * <p>TODO(bleichen): Surely there must be a better way to catch exceptions in threads in unit
   * tests. junit ought to do this. However, at least for some setups, tests can pass despite
   * uncaught exceptions in threads.
   *
   * <p>TODO(bleichen): Nonce reuse of non-deterministic signatures.
   *
   * <p>TODO(bleichen): Overwriting nonces in deterministic signature schemes.
   */
  public static class ExceptionHandler implements Thread.UncaughtExceptionHandler {

    private Throwable firstException = null;

    @Override
    public void uncaughtException(Thread thread, Throwable ex) {
      if (firstException == null) {
        firstException = ex;
      }
    }

    public void check() throws Exception {
      if (firstException != null) {
        throw new Exception("Thread failed", firstException);
      }
    }
  }

  /** A thread that signs the same message multiple times. */
  public static class SigningThread extends Thread {
    private PublicKeySign signer;
    private Set<String> signatures;
    private byte[] message;
    private int count;

    /**
     * Constructs a thread that generates a number of signatures of a given message.
     *
     * @param signer an instance that is signing messages.
     * @param signatures a set to which the generated signatures are added. This must be a
     *     synchronized set if it is shared among multiple threads.
     * @param message the number message to be signed.
     * @param count the number of signatures that are generated.
     */
    SigningThread(PublicKeySign signer, Set<String> signatures, byte[] message, int count) {
      this.signer = signer;
      this.signatures = signatures;
      this.message = message;
      this.count = count;
    }

    /**
     * Read the plaintext from the channel. This implementation assumes that the channel is blocking
     * and throws an AssertionError if an attempt to read plaintext from the channel is incomplete.
     */
    @Override
    public void run() {
      try {
        for (int i = 0; i < count; i++) {
          byte[] signature = signer.sign(message);
          signatures.add(TestUtil.hexEncode(signature));
        }
      } catch (Exception ex) {
        getUncaughtExceptionHandler().uncaughtException(this, ex);
      }
    }
  }

  /**
   * Sign distinct messages concurrently in multiple threads. The purpose of this test is to find
   * deterministic signatures schemes, that share state to compute nonces.
   */
  public void testSigningDistinctMessages(
      PublicKeySign signer,
      PublicKeyVerify verifier,
      boolean isDeterministic,
      int maxMessageSize,
      int numberOfThreads,
      int numberOfSignatures)
      throws Exception {
    ExceptionHandler exceptionHandler = new ExceptionHandler();
    Thread[] thread = new Thread[numberOfThreads];
    ArrayList<HashSet<String>> signatures = new ArrayList<HashSet<String>>();
    byte[][] messages = new byte[numberOfThreads][];
    for (int i = 0; i < numberOfThreads; i++) {
      // Just an arbitrary prime to get the plaintext sizes.
      int p = 28657;
      int size = i * p % (maxMessageSize + 1);
      messages[i] = new byte[size];
      HashSet<String> sigs = new HashSet<String>();
      signatures.add(sigs);
      thread[i] = new SigningThread(signer, sigs, messages[i], numberOfSignatures);
      thread[i].setUncaughtExceptionHandler(exceptionHandler);
    }
    for (int i = 0; i < numberOfThreads; i++) {
      thread[i].start();
    }
    for (int i = 0; i < numberOfThreads; i++) {
      thread[i].join();
    }
    exceptionHandler.check();
    if (isDeterministic) {
      for (int i = 0; i < numberOfThreads; i++) {
        String expectedSignature = TestUtil.hexEncode(signer.sign(messages[i]));
        assertEquals(1, signatures.get(i).size());
        assertTrue(signatures.get(i).contains(expectedSignature));
      }
    } else {
      for (int i = 0; i < numberOfThreads; i++) {
        assertEquals(numberOfSignatures, signatures.get(i).size());
        for (String sig : signatures.get(i)) {
          verifier.verify(TestUtil.hexDecode(sig), messages[i]);
        }
      }
    }
  }

  /**
   * Sign the same message concurrently in multiple threads. The purpose of this test is to find
   * non-deterministic signatures schemes, that reuse nonces when signing concurrently.
   */
  public void testSigningSameMessage(
      PublicKeySign signer,
      PublicKeyVerify verifier,
      boolean isDeterministic,
      byte[] message,
      int numberOfThreads,
      int numberOfSignatures)
      throws Exception {
    // TODO(b/148134669): Remove the following line.
    // There is a potential (but unlikely) race in java.security.Provider. In some cases, we only
    // initalize some of the java.security.Providers the first time we sign. If we do this
    // multithreaded, there is a potential for a race. To get around this, we first sign once, to
    // initialize everything.
    signer.sign(message);

    ExceptionHandler exceptionHandler = new ExceptionHandler();
    Thread[] thread = new Thread[numberOfThreads];
    ArrayList<HashSet<String>> signatures = new ArrayList<HashSet<String>>();
    for (int i = 0; i < numberOfThreads; i++) {
      HashSet<String> sigs = new HashSet<String>();
      signatures.add(sigs);
      thread[i] = new SigningThread(signer, sigs, message, numberOfSignatures);
      thread[i].setUncaughtExceptionHandler(exceptionHandler);
    }
    for (int i = 0; i < numberOfThreads; i++) {
      thread[i].start();
    }
    for (int i = 0; i < numberOfThreads; i++) {
      thread[i].join();
    }
    exceptionHandler.check();

    if (isDeterministic) {
      String expectedSignature = TestUtil.hexEncode(signer.sign(message));
      for (int i = 0; i < numberOfThreads; i++) {
        assertEquals(1, signatures.get(i).size());
        assertTrue(signatures.get(i).contains(expectedSignature));
      }
    } else {
      HashSet<String> allSignatures = new HashSet<String>();
      for (int i = 0; i < numberOfThreads; i++) {
        for (String sig : signatures.get(i)) {
          verifier.verify(TestUtil.hexDecode(sig), message);
          assertFalse(allSignatures.contains(sig));
          allSignatures.add(sig);
        }
      }
      assertEquals(numberOfThreads * numberOfSignatures, allSignatures.size());
    }
  }

  @Test
  public void testEcdsa() throws Exception {
    ECParameterSpec ecParams = EllipticCurves.getNistP256Params();
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(ecParams);
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();
    EcdsaSignJce signer = new EcdsaSignJce(priv, HashType.SHA256, EcdsaEncoding.DER);
    EcdsaVerifyJce verifier = new EcdsaVerifyJce(pub, HashType.SHA256, EcdsaEncoding.DER);

    byte[] msg = Random.randBytes(20);
    testSigningSameMessage(signer, verifier, false, msg, 5, 20);
    testSigningDistinctMessages(signer, verifier, false, 64, 5, 20);
  }

  @Test
  public void testEddsa() throws Exception {
    Ed25519Sign.KeyPair keyPair = Ed25519Sign.KeyPair.newKeyPair();
    Ed25519Sign signer = new Ed25519Sign(keyPair.getPrivateKey());
    Ed25519Verify verifier = new Ed25519Verify(keyPair.getPublicKey());

    byte[] msg = Random.randBytes(20);
    testSigningSameMessage(signer, verifier, true, msg, 5, 20);
    testSigningDistinctMessages(signer, verifier, true, 64, 5, 20);
  }
}
