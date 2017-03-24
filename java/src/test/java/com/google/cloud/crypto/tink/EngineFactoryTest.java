
package com.google.cloud.crypto.tink;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.security.KeyPairGenerator;
import javax.crypto.Cipher;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for EngineFactory.
 */
@RunWith(JUnit4.class)
public class EngineFactoryTest {

  @Test
  public void testAtLeastGetsACipherByDefault() throws Exception {
    EngineFactory.CIPHER.getInstance("AES");
    // didn't throw
  }


  @Test // A bunch of default settings for a regular JVM.
  public void testCustomListOfProviders() throws Exception {
    Cipher c = EngineFactory.getCustomCipherProvider(true, "X", "Y").getInstance("AES");
    KeyPairGenerator kpg = EngineFactory.getCustomKeyPairGeneratorProvider(true, "X", "Y").getInstance("EC");
    assertEquals("SUN", Security.getProviders()[0].getName()); // The first provider
    assertEquals("SunJCE", c.getProvider().getName()); // The first one to implement AES
    assertEquals("SunEC", kpg.getProvider().getName()); // The first one to implement EC stuff


    kpg = EngineFactory.getCustomKeyPairGeneratorProvider(false, "SunEC").getInstance("EC");
    c = EngineFactory.getCustomCipherProvider(false, "SunJCE").getInstance("AES");


    try {
      EngineFactory.getCustomCipherProvider(false, "SunEC").getInstance("AES");
      fail();
    } catch (GeneralSecurityException e) {
      //expected
    }
    try {
      EngineFactory.getCustomKeyPairGeneratorProvider(false, "SunJCE").getInstance("AES");
      fail();
    } catch (GeneralSecurityException e) {
      //expected
    }
  }


  @Test
  public void testNoProviders() throws Exception {
    try {
      EngineFactory.getCustomCipherProvider(false).getInstance("AES");
      fail();
    } catch (GeneralSecurityException e) {
      //expected
    }

    try {
      EngineFactory.getCustomCipherProvider(true).getInstance("I don't exist, no point trying");
      fail();
    } catch (GeneralSecurityException e) {
      //expected
    }

    try {
      EngineFactory.getCustomKeyPairGeneratorProvider(false, "SunJCE").getInstance("EC");
      fail();
    } catch (GeneralSecurityException e) {
      //expected
    }
  }


  @Test
  public void testIsReuseable() throws Exception {
    EngineFactory.CIPHER.getInstance("AES");
    EngineFactory.CIPHER.getInstance("AES");
    EngineFactory.CIPHER.getInstance("AES");
    // didn't throw
  }

}
