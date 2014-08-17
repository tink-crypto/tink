/*
 * Copyright 2014 Google. Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.k2crypto.storage.driver.impl;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.google.k2crypto.K2Exception;
import com.google.k2crypto.K2Context;
import com.google.k2crypto.storage.IllegalAddressException;
import com.google.k2crypto.storage.driver.BasicDriverTest;

import org.junit.Test;

import java.net.URI;

/**
 * Unit tests for the K2 native in-memory driver.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public class K2MemoryDriverTest extends BasicDriverTest<K2MemoryDriver> {

  // Scheme prefix to add to addresses 
  private static final String ADDRESS_PREFIX =
      K2MemoryDriver.NATIVE_SCHEME + ':';

  /**
   * Constructs the driver test class.
   */
  public K2MemoryDriverTest() {
    super(K2MemoryDriver.class);
  }
  
  /**
   * Tests that the open() method rejects all syntactically invalid
   * URI addresses.
   */
  @Test public final void testRejectBadAddresses() {
    // Test unsupported components
    checkRejectAddress(
        ADDRESS_PREFIX + "//host/path",
        IllegalAddressException.Reason.AUTHORITY_UNSUPPORTED);
    checkRejectAddress(
        ADDRESS_PREFIX + "//user@localhost:80/path",
        IllegalAddressException.Reason.AUTHORITY_UNSUPPORTED);
    checkRejectAddress(
        ADDRESS_PREFIX + "/path?que",
        IllegalAddressException.Reason.QUERY_UNSUPPORTED);
    checkRejectAddress(
        ADDRESS_PREFIX + "/path#frag",
        IllegalAddressException.Reason.FRAGMENT_UNSUPPORTED);
    
    // Test invalid schemes
    checkRejectAddress(
        "k2:/path",
        IllegalAddressException.Reason.INVALID_SCHEME);
    checkRejectAddress(
        "file:/path",
        IllegalAddressException.Reason.INVALID_SCHEME);
    
    // Test no database path
    checkRejectAddress(
        ADDRESS_PREFIX + "host",
        IllegalAddressException.Reason.MISSING_PATH);
  }

  /**
   * Tests that various addresses are normalized correctly.
   */
  @Test public final void testAddressNormalization() throws K2Exception {
    final String expected = "mem:/stuff/my%2Fkey";
    checkNormalization(expected, "/stuff/my%2Fkey");
    checkNormalization(expected, "mem:/a/../stuff/./my%2Fkey?");
    checkNormalization(expected, "./stuff/././some/a/.././../my%2Fkey#");
  }
  
  /**
   * Tests saving, loading and erasing keys. 
   */
  @Test public final void testSaveLoadErase() throws K2Exception {
    K2MemoryDriver driver = newDriver();
    try {
      driver.open(URI.create("mem:/some/key"));
      checkLoadSaveErase(driver);
    } finally {
      driver.close();
    }
  }

  /**
   * Tests that keys are only saved/loaded with respect to the context.
   */
  @Test public final void testContextSensitive() throws K2Exception {
    // Generate three drivers. First two share a context.
    K2Context context = newContext();
    K2MemoryDriver first = newDriver(context);
    K2MemoryDriver second = newDriver(context);
    K2MemoryDriver third = newDriver(newContext());
    try {
      final URI address = URI.create("mem:/sensitive/key");

      // Open and save a key to the first driver.
      first.open(address);
      first.save(MOCK_KEY);
      assertFalse(first.isEmpty());
      
      // The second driver has the same context,
      // and so should load the saved key.
      second.open(address);
      checkLoad(second, MOCK_KEY);
      
      // Similarly, erasing the key on the second
      // will erase the key on the first.
      assertTrue(second.erase());
      assertTrue(first.isEmpty());
      
      // Save another key to the second...
      second.save(EMPTY_KEY);
      assertFalse(second.isEmpty());
      // ...and open the same address on the third.
      third.open(address);
      // The third should not observe the saved key.
      assertTrue(third.isEmpty());

      // Saving a key on the third should not affect previous two drivers.
      third.save(MOCK_KEY);
      checkLoad(first, EMPTY_KEY);
      checkLoad(second, EMPTY_KEY);
      checkLoad(third, MOCK_KEY);
      
      // Same for erasing the key on each driver.
      assertTrue(first.erase());
      assertFalse(second.erase());
      assertTrue(third.erase());
      
    } finally {
      first.close();
      second.close();
      third.close();
    }
  }
}
