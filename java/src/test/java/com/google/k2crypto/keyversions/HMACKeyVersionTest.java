package com.google.k2crypto.keyversions;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.google.k2crypto.exceptions.BuilderException;
import com.google.k2crypto.exceptions.EncryptionException;
import com.google.k2crypto.keyversions.KeyVersionProto.KeyVersionData;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistry;
import com.google.protobuf.InvalidProtocolBufferException;

import org.junit.Test;

/**
 * Tests for HMACKeyVersion class
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public class HMACKeyVersionTest {

  /**
   * Tests that the HMACKeyVersion correctly saves to and loads from proto data. 
   */
  @Test
  public void testSaveLoad()
      throws BuilderException, InvalidProtocolBufferException {
    
    // Just generate a key version (use non-defaults where possible)
    HMACKeyVersion toSave = new HMACKeyVersion.Builder()
        .algorithm(HMACKeyVersion.HMAC_SHA512).build();
    // Dump its proto data bytes
    ByteString bytes = toSave.buildData().build().toByteString();
    
    // Create a proto extension registry and register HMAC extension
    // (this will normally be done by KeyVersionRegistry)
    ExtensionRegistry registry = ExtensionRegistry.newInstance();
    HmacKeyVersionProto.registerAllExtensions(registry);
    
    // Read the proto
    HMACKeyVersion loaded = new HMACKeyVersion.Builder()
        .withData(KeyVersionData.parseFrom(bytes, registry), registry).build();
    
    // Make sure the data is the same at a low-level (nothing gets lost)
    assertEquals(bytes, loaded.buildData().build().toByteString());

    // Make sure the important fields are all the same
    assertArrayEquals(
        toSave.getKeyVersionMatter(), loaded.getKeyVersionMatter());
    assertEquals(toSave.getAlgorithm(), loaded.getAlgorithm());
  }
  
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
