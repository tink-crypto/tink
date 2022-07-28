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

package com.google.crypto.tink.mac;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link MacFactory}. */
@RunWith(JUnit4.class)
public class MacFactoryTest {

  @BeforeClass
  public static void setUp() throws Exception {
    MacConfig.register();
  }

  @Test
  @SuppressWarnings("deprecation") // This is a test that the deprecated function works.
  public void deprecatedMacFactoryGetPrimitive_sameAs_keysetHandleGetPrimitive() throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("HMAC_SHA256_128BITTAG"));

    Mac mac = handle.getPrimitive(Mac.class);
    Mac factoryMac = MacFactory.getPrimitive(handle);

    byte[] data = "data".getBytes(UTF_8);
    byte[] tag = mac.computeMac(data);
    byte[] factoryTag = factoryMac.computeMac(data);

    mac.verifyMac(tag, data);
    factoryMac.verifyMac(tag, data);
    mac.verifyMac(factoryTag, data);
    factoryMac.verifyMac(factoryTag, data);

    byte[] invalid = "invalid".getBytes(UTF_8);

    assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(tag, invalid));
    assertThrows(GeneralSecurityException.class, () -> factoryMac.verifyMac(tag, invalid));
    assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(invalid, data));
    assertThrows(GeneralSecurityException.class, () -> factoryMac.verifyMac(invalid, data));
  }
}
