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

package com.google.k2crypto.storage.driver;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.k2crypto.K2Context;
import com.google.k2crypto.K2Exception;
import com.google.k2crypto.Key;
import com.google.k2crypto.exceptions.KeyVersionException;
import com.google.k2crypto.keyversions.MockKeyVersion;
import com.google.k2crypto.storage.IllegalAddressException;
import com.google.k2crypto.storage.K2Storage;
import com.google.k2crypto.storage.StorageDriverException;
import com.google.k2crypto.storage.StoreException;
import com.google.k2crypto.storage.StoreIOException;
import com.google.k2crypto.storage.driver.Driver;
import com.google.k2crypto.storage.driver.ReadableDriver;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.net.URI;
import java.util.Random;

/**
 * Boilerplate class for a storage driver JUnit test.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
@RunWith(JUnit4.class)
public abstract class BasicDriverTest<T extends Driver> {

  /**
   * An empty key (immutable) for use in testing. 
   */
  protected static final Key EMPTY_KEY = new Key();
  
  /**
   * A mock key (immutable) for use in testing. 
   */  
  protected static final Key MOCK_KEY = 
      new Key(new MockKeyVersion.Builder().comments("testing key").build()); 
  
  // Driver implementation being tested
  private final Class<T> driverClass;
  
  // Shared context and random source for testing
  private K2Context sharedContext;
  private Random sharedRandom;

  /**
   * Initializes the driver testing boilerplate. 
   * 
   * @param driverClass Driver implementation being tested.
   */
  protected BasicDriverTest(Class<T> driverClass) {
    this.driverClass = driverClass;
  }

  /**
   * Creates shared objects for use in tests. 
   */
  @Before public void setupShared() {
    sharedContext = newContext();
    sharedRandom = new Random();
  }

  /**
   * Test that the driver has a valid structure by attempting to install it.
   * This simple test applies to any driver. 
   */
  @Test public void testDriverStructure() {
    K2Storage storage = new K2Storage(getSharedContext());
    try {
      storage.installDriver(driverClass);
    } catch (StorageDriverException ex) {
      throw new AssertionError("Driver structure is bad.", ex);
    }
  }

  /**
   * Returns a shared context for initializing drivers.
   * 
   * <p>Do NOT use if it creates dependencies between individual tests! 
   */
  protected K2Context getSharedContext() {
    return sharedContext;
  }
  
  /**
   * Returns the shared random source.
   * 
   * <p>Do NOT use if it creates dependencies between individual tests or
   * causes flaky test results!
   */
  protected Random getSharedRandom() {
    return sharedRandom;
  }

  /**
   * Creates a new context for initializing drivers.
   * 
   * <p>The context will have all necessary key versions registered.
   */
  protected K2Context newContext() {
    K2Context context = new K2Context();
    try {
      context.getKeyVersionRegistry().register(MockKeyVersion.class);
    } catch (KeyVersionException ex) {
      throw new AssertionError("Could not register mock.", ex);
    }
    return context;
  }
  
  /**
   * Creates an instance of the driver initialized with the shared context.
   */
  protected T newDriver() {
    return newDriver(sharedContext);
  }
  
  /**
   * Creates an instance of the driver initialized with the specified context.
   * 
   * @param context Context to use for initializing the driver.
   */
  protected T newDriver(K2Context context) {
    T driver;
    try {
      driver = driverClass.newInstance();
    } catch (Exception ex) {
      throw new AssertionError("Could not instantiate driver.", ex);
    }
    driver.initialize(context);
    return driver;
  }
  
  /**
   * Checks that the address is rejected by the driver for the given reason.
   * 
   * @param address String address to open.
   * @param reason Reason the address is rejected.
   */
  protected void checkRejectAddress(
      String address, IllegalAddressException.Reason reason) {
    checkRejectAddress(URI.create(address), reason);
  }
  
  /**
   * Checks that the address is rejected by the driver for the given reason.
   * 
   * @param address URI address to open.
   * @param reason Reason the address is rejected.
   */
  protected void checkRejectAddress(
      URI address, IllegalAddressException.Reason reason) {
    Driver driver = newDriver();
    try {
      driver.open(address);
      fail("Should reject " + address);
    } catch (StoreException ex) {
      throw new AssertionError("Unexpected", ex);
    } catch (IllegalAddressException expected) {
      assertEquals(reason, expected.getReason());
      assertEquals(address.toString(), expected.getAddress());
    } finally {
      driver.close();
    }
  }
  
  /**
   * Checks that the address is normalized correctly. 
   * 
   * @param expected Expected result of normalization.
   * @param address Address to check.
   * 
   * @throws K2Exception if there is an unexpected failure opening the address.
   */
  protected void checkNormalization(String expected, String address)
      throws K2Exception {
    Driver driver = newDriver();
    try {
      URI result = driver.open(URI.create(address));
      assertEquals(expected, result.toString());
    } finally {
      driver.close();
    }
  }

  /**
   * Checks that a load fails on the driver because of the specified I/O reason.
   * 
   * @param driver Driver to load from.
   * @param reason Reason for the failure.
   * 
   * @throws StoreException if there is an unexpected error.
   */
  protected void checkLoadFails(
      ReadableDriver driver, StoreIOException.Reason reason)
          throws StoreException {
    assertFalse(driver.isEmpty());
    try {    
      driver.load();
      fail("Load should fail.");
    } catch (StoreIOException expected) {
      assertEquals(reason, expected.getReason());
    }
  }

  /**
   * Checks that the driver loads the given key. 
   * 
   * @param driver Driver to load from.
   * @param expected The key that should be loaded.
   * 
   * @throws StoreException if there is an unexpected error loading. 
   */
  protected void checkLoad(ReadableDriver driver, Key expected)
      throws StoreException {
    assertFalse(driver.isEmpty());
    Key loaded = driver.load();
    assertEquals(
        expected.buildData().build().toByteString(),
        loaded.buildData().build().toByteString());    
  }

  /**
   * Checks that the driver can correctly load, save and erase keys with a
   * simple test sequence. The driver must implement both {@link ReadableDriver}
   * and {@link WritableDriver}. 
   * 
   * @param driver Driver instance to test.
   * 
   * @throws StoreException if there is an unexpected error during the sequence. 
   */
  protected void checkLoadSaveErase(Driver driver) throws StoreException {
    ReadableDriver rdriver = (ReadableDriver)driver;
    WritableDriver wdriver = (WritableDriver)driver;
    
    assertFalse(wdriver.erase());
    assertTrue(rdriver.isEmpty());
    assertNull(rdriver.load());

    wdriver.save(MOCK_KEY);
    assertFalse(rdriver.isEmpty());
    checkLoad(rdriver, MOCK_KEY);
    
    wdriver.save(EMPTY_KEY);
    assertFalse(rdriver.isEmpty());
    checkLoad(rdriver, EMPTY_KEY);

    assertTrue(wdriver.erase());
    assertTrue(rdriver.isEmpty());
    assertNull(rdriver.load());
    assertFalse(wdriver.erase());
  }
  
  /**
   * Generates a random string of digits.
   * 
   * @param length Length of the string to generate.
   */
  protected String generateString(int length) {
    Random random = getSharedRandom();
    char[] buffer = new char[length];
    for (int i = buffer.length; --i >= 0; ) {
      buffer[i] = (char)('0' + random.nextInt(10)); 
    }
    return new String(buffer);
  }
}
