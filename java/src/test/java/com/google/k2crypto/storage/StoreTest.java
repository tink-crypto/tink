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

package com.google.k2crypto.storage;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.k2crypto.K2Exception;
import com.google.k2crypto.Key;
import com.google.k2crypto.K2Context;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.net.URI;

/**
 * Unit tests for the Store wrapper.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
@RunWith(JUnit4.class)
public class StoreTest {

  private static final String ADDRESS_FRAGMENT = "://my_keys";
  
  private K2Context context = null;
  private InstalledDriver normalDriver = null;
  private Key saveKey = null;
  private Key wrapKeyA = null;
  private Key wrapKeyB = null;
  
  /**
   * Creates the mock driver (and other objects) that will be passed to the
   * store for testing.
   */
  @Before public final void setUp() throws K2Exception {
    context = new K2Context();
    normalDriver = new InstalledDriver(context, MockDriver.Normal.class);
    
    // TODO(darylseah): We need a proper way to create keys for testing.
    //                  The current approach is fragile and WILL break later.
    saveKey = new Key();
    wrapKeyA = new Key();
    wrapKeyB = new Key();
  }
  
  /**
   * Tests a complete save/load/erase sequence on a store without wrapping
   * of keys. 
   */
  @Test public final void testSaveLoadErase() throws K2Exception {
    // Instantiate and check basic store fields
    URI address = URI.create(normalDriver.getId() + ADDRESS_FRAGMENT);
    Store store = new Store(normalDriver, address);
    assertEquals(normalDriver, store.getInstalledDriver());
    assertEquals(address, store.getAddress());

    // Check driver state
    MockDriver driver = (MockDriver)store.getDriver();
    assertTrue(driver.initCalled);
    assertFalse(driver.openCalled);
    assertFalse(driver.closeCalled);
    assertEquals(0, driver.wrapWithCalls);
    assertEquals(0, driver.isWrappingCalls);
    assertEquals(0, driver.isEmptyCalls);
    assertEquals(0, driver.saveCalls);
    assertEquals(0, driver.loadCalls);
    assertEquals(0, driver.eraseCalls);
    
    // Open, then check store/driver state
    assertFalse(store.isOpen());
    assertEquals(store, store.open());
    assertTrue(driver.openCalled);
    assertTrue(store.isOpen());
    assertTrue(store.isEmpty());
    assertEquals(1, driver.isEmptyCalls);
    assertFalse(store.isWrapping());
    assertEquals(1, driver.isWrappingCalls);
    assertNull(store.load());
    assertEquals(1, driver.loadCalls);
    assertFalse(store.erase());
    assertFalse(store.erase());
    assertEquals(2, driver.eraseCalls);
    
    // Save/load
    store.save(saveKey);
    assertEquals(1, driver.saveCalls);
    assertFalse(store.isEmpty());
    assertEquals(2, driver.isEmptyCalls);
    assertEquals(saveKey, driver.storedKey);
    assertEquals(saveKey, store.load());
    assertEquals(2, driver.loadCalls);
    
    // Erase store
    assertTrue(store.erase());
    assertEquals(3, driver.eraseCalls);
    assertNull(driver.storedKey);
    assertTrue(store.isEmpty());
    assertEquals(3, driver.isEmptyCalls);
    assertFalse(store.erase());
    assertEquals(4, driver.eraseCalls);
    assertNull(store.load());
    assertEquals(3, driver.loadCalls);
    
    // Check noWrap has no consequence
    assertEquals(0, driver.wrapWithCalls);
    assertEquals(store, store.noWrap());
    assertEquals(1, driver.wrapWithCalls);
    assertFalse(store.isWrapping());
    assertEquals(2, driver.isWrappingCalls);
    
    // Close store
    store.close();
    assertTrue(driver.closeCalled);
    assertFalse(store.isOpen());
  }

  /**
   * Tests saving (mainly) on a store with wrapping of keys. 
   */
  @Test public final void testSaveWithWrapping() throws K2Exception {
    URI address = URI.create(normalDriver.getId() + ADDRESS_FRAGMENT);
    Store store = new Store(normalDriver, address);
    MockDriver driver = (MockDriver)store.getDriver();
    store.open();

    // Set wrap key
    store.wrapWith(wrapKeyA);
    assertEquals(1, driver.wrapWithCalls);
    assertEquals(wrapKeyA, driver.wrapKey);
    assertTrue(store.isWrapping());
    assertEquals(1, driver.isWrappingCalls);

    // Save a key with encryption
    store.save(saveKey);
    assertEquals(1, driver.saveCalls);
    assertFalse(store.isEmpty());
    assertEquals(1, driver.isEmptyCalls);
    assertEquals(saveKey, driver.storedKey);
    assertEquals(wrapKeyA, driver.storedKeyWrapper);
    assertEquals(saveKey, store.load());
    
    // Save with another wrapping key
    store.wrapWith(wrapKeyB).save(saveKey);
    assertEquals(2, driver.wrapWithCalls);
    assertEquals(wrapKeyB, driver.wrapKey);
    assertEquals(2, driver.saveCalls);
    assertFalse(store.isEmpty());
    assertEquals(2, driver.isEmptyCalls);
    assertTrue(store.isWrapping());
    assertEquals(2, driver.isWrappingCalls);
    assertEquals(saveKey, driver.storedKey);
    assertEquals(wrapKeyB, driver.storedKeyWrapper);
    assertEquals(saveKey, store.load());
    
    // Save with no wrapping key
    store.noWrap().save(saveKey);
    assertEquals(3, driver.wrapWithCalls);
    assertNull(driver.wrapKey);
    assertEquals(3, driver.saveCalls);
    assertFalse(store.isEmpty());
    assertEquals(3, driver.isEmptyCalls);
    assertFalse(store.isWrapping());
    assertEquals(3, driver.isWrappingCalls);
    assertEquals(saveKey, driver.storedKey);
    assertNull(driver.storedKeyWrapper);
    assertEquals(saveKey, store.load());

    // Final save with first wrapping key
    store.wrapWith(wrapKeyA); // <-- redundant on purpose
    store.wrapWith(wrapKeyA).save(saveKey);
    assertEquals(5, driver.wrapWithCalls);
    assertEquals(wrapKeyA, driver.wrapKey);
    assertEquals(4, driver.saveCalls);
    assertFalse(store.isEmpty());
    assertEquals(4, driver.isEmptyCalls);
    assertTrue(store.isWrapping());
    assertEquals(4, driver.isWrappingCalls);
    assertEquals(saveKey, driver.storedKey);
    assertEquals(wrapKeyA, driver.storedKeyWrapper);
    assertEquals(saveKey, store.load());

    // Clean up store
    store.close();
    assertTrue(driver.closeCalled);
    assertFalse(store.isOpen());
  }

  /**
   * Tests loading (mainly) on a store with wrapping of keys. 
   */
  @Test public final void testLoadWithWrapping() throws K2Exception {
    URI address = URI.create(normalDriver.getId() + ADDRESS_FRAGMENT);
    Store store = new Store(normalDriver, address);
    MockDriver driver = (MockDriver)store.getDriver();
    store.open();
    
    // Set the wrapping key
    store.wrapWith(wrapKeyB);
    assertEquals(1, driver.wrapWithCalls);
    assertEquals(wrapKeyB, driver.wrapKey);
    assertTrue(store.isWrapping());
    assertEquals(1, driver.isWrappingCalls);

    // Try to load an empty store, with a wrap key (should be fine)
    assertTrue(store.isEmpty());
    assertNull(store.load());
    assertEquals(1, driver.loadCalls);

    // Save a key with encryption
    store.save(saveKey);

    // Check cannot read encrypted key without wrap key
    store.noWrap();
    assertEquals(2, driver.wrapWithCalls);
    assertNull(driver.wrapKey);
    assertFalse(store.isWrapping());
    assertEquals(2, driver.isWrappingCalls);      
    try {
      store.load();
      fail("Store should fail to load without the wrap key.");
    } catch (StoreIOException expected) {
      assertEquals(
          StoreIOException.Reason.WRAP_KEY_REQUIRED, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    assertEquals(2, driver.loadCalls);

    // Check cannot read encrypted key without correct wrap key
    store.wrapWith(wrapKeyA);
    assertEquals(3, driver.wrapWithCalls);
    assertEquals(wrapKeyA, driver.wrapKey);      
    assertTrue(store.isWrapping());
    assertEquals(3, driver.isWrappingCalls);
    try {
      store.load();
      fail("Store should fail to load without correct wrap key.");
    } catch (StoreIOException expected) {
      assertEquals(
          StoreIOException.Reason.WRAP_KEY_WRONG, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    assertEquals(3, driver.loadCalls);
    
    // Read encrypted key
    Key key = store.wrapWith(wrapKeyB).load();
    assertEquals(4, driver.wrapWithCalls);
    assertEquals(wrapKeyB, driver.wrapKey);
    assertTrue(store.isWrapping());
    assertEquals(4, driver.isWrappingCalls);      
    assertEquals(4, driver.loadCalls);      
    assertEquals(saveKey, key);
    
    // Overwrite with unencrypted key
    store.noWrap().save(saveKey);
    assertEquals(5, driver.wrapWithCalls);
    assertNull(driver.wrapKey);
    assertFalse(store.isWrapping());
    assertEquals(5, driver.isWrappingCalls);

    // Check that store won't load an unencrypted key with a wrap key 
    store.wrapWith(wrapKeyB);
    assertEquals(6, driver.wrapWithCalls);
    assertEquals(wrapKeyB, driver.wrapKey);
    assertTrue(store.isWrapping());
    assertEquals(6, driver.isWrappingCalls);      
    try {
      store.load();
      fail("Store should fail to load when wrap key is unnecessary.");
    } catch (StoreIOException expected) {
      assertEquals(
          StoreIOException.Reason.WRAP_KEY_UNNECESSARY, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    assertEquals(5, driver.loadCalls);
    
    // Load the key
    key = store.noWrap().load();
    assertEquals(7, driver.wrapWithCalls);
    assertNull(driver.wrapKey);
    assertFalse(store.isWrapping());
    assertEquals(7, driver.isWrappingCalls);
    assertEquals(6, driver.loadCalls);
    assertEquals(saveKey, key);
    
    // Clean up store
    store.close();
  }

  /**
   * Tests erasing (mainly) on a store with wrapping of keys. 
   */
  @Test public final void testEraseWithWrapping() throws K2Exception {
    URI address = URI.create(normalDriver.getId() + ADDRESS_FRAGMENT);
    Store store = new Store(normalDriver, address);
    MockDriver driver = (MockDriver)store.getDriver();
    store.open();
    
    // Set the wrapping key
    store.wrapWith(wrapKeyA);
    assertEquals(1, driver.wrapWithCalls);

    // Erase an empty store, twice.
    // Check that wrap key is still there.
    assertTrue(store.isEmpty());
    assertFalse(store.erase());
    assertEquals(1, driver.eraseCalls);
    assertFalse(store.erase());
    assertEquals(2, driver.eraseCalls);
    assertEquals(wrapKeyA, driver.wrapKey);
    assertTrue(store.isWrapping());
    assertEquals(1, driver.isWrappingCalls);

    // Save a key with encryption
    store.save(saveKey);

    // Erase and check state
    assertFalse(store.isEmpty());
    assertTrue(store.erase());
    assertEquals(3, driver.eraseCalls);
    assertNull(driver.storedKey);
    assertNull(driver.storedKeyWrapper);
    assertTrue(store.isEmpty());
    assertNull(store.load());
    
    // Change wrapping key
    store.wrapWith(wrapKeyB);
    assertEquals(2, driver.wrapWithCalls);
    
    // Erase again, check that wrap key is still there
    assertFalse(store.erase());
    assertEquals(4, driver.eraseCalls);
    assertEquals(wrapKeyB, driver.wrapKey);
    assertTrue(store.isWrapping());
    assertEquals(2, driver.isWrappingCalls);
    
    // Clean up store
    store.close();
  }

  /**
   * Tests that most methods will not work unless the store is opened.  
   */
  @Test public final void testAccessBeforeOpen() throws K2Exception {
    URI address = URI.create(normalDriver.getId() + ADDRESS_FRAGMENT);
    Store store = new Store(normalDriver, address);
    MockDriver driver = (MockDriver)store.getDriver();
    
    // All method calls below should fail
    try {
      store.wrapWith(wrapKeyA);
      fail("WrapWith permits access before open.");
    } catch (StoreStateException expected) {
      assertEquals(StoreStateException.Reason.NOT_OPEN, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    try {
      store.noWrap();
      fail("NoWrap permits access before open.");
    } catch (StoreStateException expected) {
      assertEquals(StoreStateException.Reason.NOT_OPEN, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    try {
      store.isWrapping();
      fail("IsWrapping permits access before open.");
    } catch (StoreStateException expected) {
      assertEquals(StoreStateException.Reason.NOT_OPEN, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    try {
      store.isEmpty();
      fail("IsEmpty permits access before open.");
    } catch (StoreStateException expected) {
      assertEquals(StoreStateException.Reason.NOT_OPEN, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    try {
      store.save(saveKey);
      fail("Save permits access before open.");
    } catch (StoreStateException expected) {
      assertEquals(StoreStateException.Reason.NOT_OPEN, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    try {
      store.load();
      fail("Load permits access before open.");
    } catch (StoreStateException expected) {
      assertEquals(StoreStateException.Reason.NOT_OPEN, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    try {
      store.erase();
      fail("Erase permits access before open.");
    } catch (StoreStateException expected) {
      assertEquals(StoreStateException.Reason.NOT_OPEN, expected.getReason());
      assertEquals(store, expected.getStore());
    }

    // The driver should not see any of the calls
    assertFalse(driver.openCalled);
    assertFalse(driver.closeCalled);
    assertEquals(0, driver.wrapWithCalls);
    assertEquals(0, driver.isWrappingCalls);
    assertEquals(0, driver.isEmptyCalls);
    assertEquals(0, driver.saveCalls);
    assertEquals(0, driver.loadCalls);
    assertEquals(0, driver.eraseCalls);
    store.open();
    assertTrue(driver.openCalled);
    store.close();
    assertTrue(driver.closeCalled);
  }
  
  /**
   * Tests that most methods will not work after the store is closed.  
   */
  @Test public final void testAccessAfterClose() throws K2Exception {
    URI address = URI.create(normalDriver.getId() + ADDRESS_FRAGMENT);
    Store store = new Store(normalDriver, address);
    MockDriver driver = (MockDriver)store.getDriver();

    // Straight to closed state without open 
    store.close();
    
    // Close on the driver should only be called if we opened first.
    assertFalse(driver.closeCalled);
    
    // All method calls below should fail
    try {
      store.open();
      fail("Open permits access after close.");
    } catch (StoreStateException expected) {
      assertEquals(
          StoreStateException.Reason.ALREADY_CLOSED, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    try {
      store.wrapWith(wrapKeyA);
      fail("WrapWith permits access after close.");
    } catch (StoreStateException expected) {
      assertEquals(
          StoreStateException.Reason.ALREADY_CLOSED, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    try {
      store.noWrap();
      fail("NoWrap permits access after close.");
    } catch (StoreStateException expected) {
      assertEquals(
          StoreStateException.Reason.ALREADY_CLOSED, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    try {
      store.isWrapping();
      fail("IsWrapping permits access after close.");
    } catch (StoreStateException expected) {
      assertEquals(
          StoreStateException.Reason.ALREADY_CLOSED, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    try {
      store.isEmpty();
      fail("IsEmpty permits access after close.");
    } catch (StoreStateException expected) {
      assertEquals(
          StoreStateException.Reason.ALREADY_CLOSED, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    try {
      store.save(saveKey);
      fail("Save permits access after close.");
    } catch (StoreStateException expected) {
      assertEquals(
          StoreStateException.Reason.ALREADY_CLOSED, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    try {
      store.load();
      fail("Load permits access after close.");
    } catch (StoreStateException expected) {
      assertEquals(
          StoreStateException.Reason.ALREADY_CLOSED, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    try {
      store.erase();
      fail("Erase permits access after close.");
    } catch (StoreStateException expected) {
      assertEquals(
          StoreStateException.Reason.ALREADY_CLOSED, expected.getReason());
      assertEquals(store, expected.getStore());
    }

    // The driver should not see any of the calls
    assertFalse(driver.openCalled);
    assertEquals(0, driver.wrapWithCalls);
    assertEquals(0, driver.isWrappingCalls);
    assertEquals(0, driver.isEmptyCalls);
    assertEquals(0, driver.saveCalls);
    assertEquals(0, driver.loadCalls);
    assertEquals(0, driver.eraseCalls);
  }
  
  /**
   * Tests that save(Key) and erase() do not work on a read-only driver.  
   */
  @Test public final void testAccessForReadOnlyDriver() throws K2Exception {
    InstalledDriver readOnlyDriver =
        new InstalledDriver(context, MockDriver.ReadOnly.class);
    URI address = URI.create(readOnlyDriver.getId() + ADDRESS_FRAGMENT);
    Store store = new Store(readOnlyDriver, address);
    assertEquals(readOnlyDriver, store.getInstalledDriver());
    MockDriver driver = (MockDriver)store.getDriver();
    store.open();
    
    // Save and erase should fail
    try {
      store.save(saveKey);
      fail("Save works for read-only driver.");
    } catch (UnsupportedByStoreException expected) {
      assertEquals(
          UnsupportedByStoreException.Reason.READ_ONLY, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    try {
      store.erase();
      fail("Erase works for read-only driver.");
    } catch (UnsupportedByStoreException expected) {
      assertEquals(
          UnsupportedByStoreException.Reason.READ_ONLY, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    
    // ...even with a wrapping key (sanity check)
    store.wrapWith(wrapKeyA);
    try {
      store.save(saveKey);
      fail("Save works for read-only driver with a wrapping key.");
    } catch (UnsupportedByStoreException expected) {
      assertEquals(
          UnsupportedByStoreException.Reason.READ_ONLY, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    try {
      store.erase();
      fail("Erase works for read-only driver with a wrapping key.");
    } catch (UnsupportedByStoreException expected) {
      assertEquals(
          UnsupportedByStoreException.Reason.READ_ONLY, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    
    // The remaining method calls should work
    assertEquals(store, store.noWrap());
    assertFalse(store.isWrapping());
    assertTrue(store.isEmpty());
    assertNull(store.load());

    // The driver should only see permitted calls
    assertEquals(2, driver.wrapWithCalls);
    assertEquals(1, driver.isWrappingCalls);
    assertEquals(1, driver.isEmptyCalls);
    assertEquals(1, driver.loadCalls);
    assertEquals(0, driver.saveCalls);
    assertEquals(0, driver.eraseCalls);
    store.close();
  }
  
  /**
   * Tests that load() and isEmpty() do not work on a write-only driver.  
   */
  @Test public final void testAccessForWriteOnlyDriver() throws K2Exception {
    InstalledDriver writeOnlyDriver =
        new InstalledDriver(context, MockDriver.WriteOnly.class);
    URI address = URI.create(writeOnlyDriver.getId() + ADDRESS_FRAGMENT);
    Store store = new Store(writeOnlyDriver, address);
    assertEquals(writeOnlyDriver, store.getInstalledDriver());
    MockDriver driver = (MockDriver)store.getDriver();
    store.open();
    
    // Load and isEmpty should fail
    try {
      store.load();
      fail("Load works for write-only driver.");
    } catch (UnsupportedByStoreException expected) {
      assertEquals(
          UnsupportedByStoreException.Reason.WRITE_ONLY, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    try {
      store.isEmpty();
      fail("IsEmpty works for write-only driver.");
    } catch (UnsupportedByStoreException expected) {
      assertEquals(
          UnsupportedByStoreException.Reason.WRITE_ONLY, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    
    // ...even with a wrapping key (sanity check)
    store.wrapWith(wrapKeyA);
    try {
      store.load();
      fail("Load works for write-only driver with a wrapping key.");
    } catch (UnsupportedByStoreException expected) {
      assertEquals(
          UnsupportedByStoreException.Reason.WRITE_ONLY, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    try {
      store.isEmpty();
      fail("IsEmpty works for write-only driver with a wrapping key.");
    } catch (UnsupportedByStoreException expected) {
      assertEquals(
          UnsupportedByStoreException.Reason.WRITE_ONLY, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    
    // The remaining method calls should work
    assertEquals(store, store.noWrap());
    assertFalse(store.isWrapping());
    store.save(saveKey);
    assertTrue(store.erase());
    assertFalse(store.erase());

    // The driver should only see permitted calls
    assertEquals(2, driver.wrapWithCalls);
    assertEquals(1, driver.isWrappingCalls);
    assertEquals(0, driver.isEmptyCalls);
    assertEquals(0, driver.loadCalls);
    assertEquals(1, driver.saveCalls);
    assertEquals(2, driver.eraseCalls);
    store.close();
  }
  
  /**
   * Tests that wrapWith() and noWrap()/isWrapping() do not work on a
   * no-wrap driver.  
   */
  @Test public final void testAccessForNoWrapDriver() throws K2Exception {
    InstalledDriver noWrapDriver =
        new InstalledDriver(context, MockDriver.NoWrap.class);
    URI address = URI.create(noWrapDriver.getId() + ADDRESS_FRAGMENT);
    Store store = new Store(noWrapDriver, address);
    assertEquals(noWrapDriver, store.getInstalledDriver());
    MockDriver driver = (MockDriver)store.getDriver();
    store.open();
    
    // wrapWith should fail
    try {
      store.wrapWith(wrapKeyA);
      fail("WrapWith works for no-wrap driver.");
    } catch (UnsupportedByStoreException expected) {
      assertEquals(
          UnsupportedByStoreException.Reason.NO_WRAP, expected.getReason());
      assertEquals(store, expected.getStore());
    }
    
    // noWrap and isWrapping should have no effect
    assertEquals(store, store.noWrap());
    assertFalse(store.isWrapping());

    // The remaining method calls should work
    store.save(saveKey);
    assertEquals(saveKey, store.load());
    assertTrue(store.erase());
    assertTrue(store.isEmpty());

    // The driver should only see permitted calls
    assertEquals(0, driver.wrapWithCalls);
    assertEquals(0, driver.isWrappingCalls);
    assertEquals(1, driver.isEmptyCalls);
    assertEquals(1, driver.loadCalls);
    assertEquals(1, driver.saveCalls);
    assertEquals(1, driver.eraseCalls);
    store.close();
  }

  /**
   * Tests that a store properly changes its address to match the one provided
   * by the driver. 
   */
  @Test public final void testAddressChangeDriver() throws K2Exception {
    InstalledDriver acceptAllDriver =
        new InstalledDriver(context, MockDriver.AcceptAll.class);
    URI address = URI.create("file" + ADDRESS_FRAGMENT);
    Store store = new Store(acceptAllDriver, address);
    assertEquals(acceptAllDriver, store.getInstalledDriver());
    assertEquals(address, store.getAddress());
    store.open();
    assertEquals(
        URI.create(acceptAllDriver.getId() + ADDRESS_FRAGMENT),
        store.getAddress());
    store.close();
  }

  /**
   * Tests that wrapWith() and save() reject null keys.  
   */
  @Test public final void testRejectNulls() throws K2Exception {
    URI address = URI.create(normalDriver.getId() + ADDRESS_FRAGMENT);
    Store store = new Store(normalDriver, address);
    MockDriver driver = (MockDriver)store.getDriver();
    store.open();
    
    // WrapWith should fail
    try {
      store.wrapWith(null);
      fail("WrapWith works with a null key.");
    } catch (NullPointerException expected) {
      assertEquals("key", expected.getMessage());
    }
    assertFalse(store.isWrapping());
    
    // Save should fail
    try {
      store.save(null);
      fail("Save works with a null key.");
    } catch (NullPointerException expected) {
      assertEquals("key", expected.getMessage());
    }
    assertTrue(store.isEmpty());

    // The driver should not see wrapWith and save
    assertEquals(0, driver.wrapWithCalls);
    assertEquals(1, driver.isWrappingCalls);
    assertEquals(0, driver.saveCalls);
    assertEquals(1, driver.isEmptyCalls);
    assertEquals(0, driver.loadCalls);
    assertEquals(0, driver.eraseCalls);
    store.close();
  }
}
