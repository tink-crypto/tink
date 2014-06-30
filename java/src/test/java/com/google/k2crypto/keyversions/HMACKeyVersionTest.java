package com.google.k2crypto.keyversions;

import static org.junit.Assert.assertTrue;

import com.google.k2crypto.exceptions.BuilderException;
import com.google.k2crypto.exceptions.EncryptionException;

import org.junit.Test;

/**
 * Tests for HMACKeyVersion class
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public class HMACKeyVersionTest {

  /**
   * Tests the HMACKeyVersion functionality. Generates an HMAC key version, uses it to generate
   * HMAC, then generates a second HMAC key version using the raw byte representation of the first
   * key version, and then uses it to verify the HMAC. Tests all algorithms.
   *
   * @throws BuilderException
   * @throws EncryptionException
   */
  @Test
  public void testHMACKeyVersion() throws BuilderException, EncryptionException {
    // test all hash algorithms
    for (String algorithm : new String[] {HMACKeyVersion.HMAC_MD5, HMACKeyVersion.HMAC_SHA1,
        HMACKeyVersion.HMAC_SHA256, HMACKeyVersion.HMAC_SHA384, HMACKeyVersion.HMAC_SHA512}) {
      // create HMACKeyVersion
      HMACKeyVersion keyversion = HMACKeyVersion.generateHMAC(algorithm);
      // test input message
      String message = "weak";
      // compute HMAC on message
      byte[] hmac = keyversion.getRawHMAC(message.getBytes());

      // now get the raw bytes of the key version
      byte[] keyVersionMatter = keyversion.getKeyVersionMatter();

      // create second keyversion from the raw keyversion matter
      HMACKeyVersion keyversion2 =
          HMACKeyVersion.generateHMAC(algorithm, keyVersionMatter);

      // use the original keyversion to verify the HMAC
      assertTrue(keyversion.verifyHMAC(hmac, message.getBytes()));

      // use the new keyversion to verify the HMAC
      assertTrue(keyversion2.verifyHMAC(hmac, message.getBytes()));
    }
  }
}
