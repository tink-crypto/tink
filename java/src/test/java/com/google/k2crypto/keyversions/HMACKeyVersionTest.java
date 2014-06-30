package com.google.k2crypto.keyversions;

import static org.junit.Assert.assertTrue;

import com.google.k2crypto.exceptions.BuilderException;
import com.google.k2crypto.exceptions.SigningException;

import org.junit.Test;

/**
 * Tests for HMACKeyVersion class
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public class HMACKeyVersionTest {


  @Test
  public void testHMACKeyVersion() throws BuilderException, SigningException {
    // create HMACKeyVersion
    HMACKeyVersion keyversion = HMACKeyVersion.generateSHA1HMAC();
    // test input message
    String message = "weak";
    // compute HMAC on message
    byte[] hmac = keyversion.getRawHMAC(message.getBytes());

    // now get the raw bytes of the key versiohn
    byte[] keyVersionMatter = keyversion.getKeyVersionMatter();

    // create second keyversion from the raw keyversion matter
    HMACKeyVersion keyversion2 = HMACKeyVersion.generateSHA1HMAC(keyVersionMatter);

    // use the original keyversion to verify the HMAC
    assertTrue(keyversion.verifyHMAC(hmac, message.getBytes()));

    // use the new keyversion to verify the HMAC
    assertTrue(keyversion2.verifyHMAC(hmac, message.getBytes()));

  }

}
