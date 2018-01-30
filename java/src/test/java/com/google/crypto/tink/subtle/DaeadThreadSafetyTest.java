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

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.TestUtil;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Test for thread safety of {@code DeterministicAead}-primitives.
 *
 * <p>If possible then this unit test should be run using a thread sanitizer. Otherwise only race
 * conditions that actually happend during the test will be detected.
 */
@RunWith(JUnit4.class)
public class DaeadThreadSafetyTest {

  /**
   * Exception handler for uncaught exceptions in a thread.
   *
   * <p>TODO(bleichen): Surely there must be a better way to catch exceptions in threads in unit
   * tests. junit ought to do this. However, at least for some setups, tests can pass despite
   * uncaught exceptions in threads.
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

  /** A thread that encrypts and decrypts random plaintexts. */
  public static class CryptingThread extends Thread {
    private DeterministicAead cipher;
    private int maxPlaintextSize;
    private int count;

    /**
     * Constructs a thread that encrypts and decrypts a number of plaintexts.
     *
     * @param maxPlaintextSize the maximal size of a plaintext
     * @param count the number of encryptions and decryptions done in the test
     */
    CryptingThread(DeterministicAead cipher, int maxPlaintextSize, int count) {
      this.cipher = cipher;
      this.maxPlaintextSize = maxPlaintextSize;
      this.count = count;
    }

    /**
     * Read the plaintext from the channel. This implementation assumes that the channel is blocking
     * and throws an AssertionError if an attempt to read plaintext from the channel is incomplete.
     */
    @Override
    public void run() {
      try {
        // Just an arbitrary prime to get the plaintext sizes.
        int p = 28657;
        for (int i = 0; i < count; i++) {
          // All sizes are used once when count > maxPlaintextSize.
          int size = i * p % (maxPlaintextSize + 1);
          int aadSize = (i / 2) * p % (maxPlaintextSize + 1);
          byte[] plaintext = new byte[size];
          byte[] aad = new byte[aadSize];
          byte[] ciphertext = cipher.encryptDeterministically(plaintext, aad);
          byte[] ciphertext2 = cipher.encryptDeterministically(plaintext, aad);
          TestUtil.assertByteArrayEquals("Encryption not deterministic", ciphertext, ciphertext2);
          byte[] decrypted = cipher.decryptDeterministically(ciphertext, aad);
          TestUtil.assertByteArrayEquals("Incorrect decryption", plaintext, decrypted);
        }
      } catch (Exception ex) {
        getUncaughtExceptionHandler().uncaughtException(this, ex);
      }
    }
  }

  /** Encrypt and decrypt concurrently with one DeterministicAead cipher. */
  public void testEncryptionDecryption(
      DeterministicAead cipher,
      int numberOfThreads,
      int maxPlaintextSize,
      int numberOfEncryptionsPerThread)
      throws Exception {
    ExceptionHandler exceptionHandler = new ExceptionHandler();
    Thread[] thread = new Thread[numberOfThreads];
    for (int i = 0; i < numberOfThreads; i++) {
      thread[i] = new CryptingThread(cipher, maxPlaintextSize, numberOfEncryptionsPerThread);
      thread[i].setUncaughtExceptionHandler(exceptionHandler);
    }
    for (int i = 0; i < numberOfThreads; i++) {
      thread[i].start();
    }
    for (int i = 0; i < numberOfThreads; i++) {
      thread[i].join();
    }
    exceptionHandler.check();
  }

  @Test
  public void testAesSiv192() throws Exception {
    byte[] key = Random.randBytes(48);
    AesSiv siv;
    try {
      siv = new AesSiv(key);
    } catch (GeneralSecurityException ex) {
      System.out.println("Skipping test: AES-SIV with 192 bit AES keys is not supported.");
      return;
    }
    testEncryptionDecryption(siv, 5, 128, 20);
  }

  @Test
  public void testAesSiv256() throws Exception {
    byte[] key = Random.randBytes(64);
    AesSiv siv;
    try {
      siv = new AesSiv(key);
    } catch (GeneralSecurityException ex) {
      System.out.println("Skipping test: AES-SIV with 256 bit AES keys is not supported.");
      return;
    }
    testEncryptionDecryption(siv, 5, 128, 20);
  }
}
