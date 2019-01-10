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

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.TestUtil;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Test for thread safety of {@code Aead}-primitives.
 *
 * <p>If possible then this unit test should be run using a thread sanitizer. Otherwise only race
 * conditions that actually happend during the test will be detected.
 *
 * <p>There are a few things that this test can't check: One of the goal of Tink is to achieve
 * robust interfaces. In particular, no matter how the primitives are called there should be no way
 * to leak the private key. Ideally, this guarantee should also cover modifying the input arrays in
 * a concurrent thread while the primitive is encrypting. If a thread modifies the input arrays
 * while the primitive is encrypting then this modification must not lead to ciphertext that leaks
 * information about the key. If it does leak then the implementation should be modified to either
 * lock the input or clone it before encrypting.
 */
@RunWith(JUnit4.class)
public class AeadThreadSafetyTest {

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
    private Aead cipher;
    private int maxPlaintextSize;
    private int count;

    /**
     * Constructs a thread that encrypts and decrypts a number of plaintexts.
     *
     * @param maxPlaintextSize the maximal size of a plaintext
     * @param count the number of encryptions and decryptions done in the test
     */
    CryptingThread(Aead cipher, int maxPlaintextSize, int count) {
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
          byte[] ciphertext = cipher.encrypt(plaintext, aad);
          byte[] decrypted = cipher.decrypt(ciphertext, aad);
          TestUtil.assertByteArrayEquals("Incorrect decryption", plaintext, decrypted);
        }
      } catch (Exception ex) {
        getUncaughtExceptionHandler().uncaughtException(this, ex);
      }
    }
  }

  /** Encrypt and decrypt concurrently with one Aead cipher. */
  public void testEncryptionDecryption(
      Aead cipher, int numberOfThreads, int maxPlaintextSize, int numberOfEncryptionsPerThread)
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
  public void testAesGcm() throws Exception {
    byte[] key = Random.randBytes(16);
    AesGcmJce gcm = new AesGcmJce(key);
    testEncryptionDecryption(gcm, 5, 128, 20);
  }

  @Test
  public void testAesEax() throws Exception {
    byte[] key = Random.randBytes(16);
    AesEaxJce eax = new AesEaxJce(key, 12);
    testEncryptionDecryption(eax, 5, 128, 20);
  }

  @Test
  public void testAesCtrHmac() throws Exception {
    byte[] key = Random.randBytes(16);
    byte[] macKey = Random.randBytes(32);
    int ivSize = 12;
    int macSize = 12;
    IndCpaCipher cipher = new AesCtrJceCipher(key, ivSize);
    SecretKeySpec keySpec = new SecretKeySpec(macKey, "HMAC");
    Mac mac = new MacJce("HMACSHA256", keySpec, macSize);
    Aead aesCtrHmac = new EncryptThenAuthenticate(cipher, mac, macSize);
    testEncryptionDecryption(aesCtrHmac, 5, 128, 20);
  }

  @Test
  public void testChaChaPoly1305() throws Exception {
    byte[] key = Random.randBytes(32);
    Aead cipher = new ChaCha20Poly1305(key);
    testEncryptionDecryption(cipher, 5, 128, 20);
  }

  @Test
  public void testXChaChaPoly1305() throws Exception {
    byte[] key = Random.randBytes(32);
    Aead cipher = new XChaCha20Poly1305(key);
    testEncryptionDecryption(cipher, 5, 128, 20);
  }
}
