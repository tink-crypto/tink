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
import static org.junit.Assert.fail;

import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.Security;
import javax.crypto.Cipher;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for EngineFactory. */
@RunWith(JUnit4.class)
public class EngineFactoryTest {

  @Test
  public void testAtLeastGetsACipherByDefault() throws Exception {
    EngineFactory.CIPHER.getInstance("AES");
    // didn't throw
  }

  @Test // A bunch of default settings for a regular JVM.
  public void testCustomListOfProviders() throws Exception {
    if (SubtleUtil.isAndroid()) {
      // Android doesn't have SUN, SunJCE, or SunEC provider.
      return;
    }

    Cipher c = EngineFactory.getCustomCipherProvider(true, "X", "Y").getInstance("AES");
    KeyPairGenerator kpg =
        EngineFactory.getCustomKeyPairGeneratorProvider(true, "X", "Y").getInstance("EC");
    assertEquals("SUN", Security.getProviders()[0].getName()); // The first provider
    assertEquals("SunJCE", c.getProvider().getName()); // The first one to implement AES
    assertEquals("SunEC", kpg.getProvider().getName()); // The first one to implement EC stuff

    kpg = EngineFactory.getCustomKeyPairGeneratorProvider(false, "SunEC").getInstance("EC");
    c = EngineFactory.getCustomCipherProvider(false, "SunJCE").getInstance("AES");

    try {
      EngineFactory.getCustomCipherProvider(false, "SunEC").getInstance("AES");
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
    try {
      EngineFactory.getCustomKeyPairGeneratorProvider(false, "SunJCE").getInstance("AES");
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void testNoProviders() throws Exception {
    try {
      EngineFactory.getCustomCipherProvider(false).getInstance("AES");
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }

    try {
      EngineFactory.getCustomCipherProvider(true).getInstance("I don't exist, no point trying");
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }

    try {
      EngineFactory.getCustomKeyPairGeneratorProvider(false, "SunJCE").getInstance("EC");
      fail();
    } catch (GeneralSecurityException e) {
      // expected
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
