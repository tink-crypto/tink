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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.k2crypto.K2Context;
import com.google.k2crypto.K2Exception;
import com.google.k2crypto.storage.driver.Driver;
import com.google.k2crypto.storage.driver.DriverInfo;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.net.URI;
import java.util.List;

/**
 * Unit tests for K2Storage.
 * 
 * <p>Verifies that driver installation/uninstallation is working and that
 * locating the appropriate store driver for a storage address has correct
 * behavior.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
@RunWith(JUnit4.class)
public class K2StorageTest {
  
  private K2Context context = null;
 
  /**
   * Creates a context for the tests.
   */
  @Before public final void setUp() {
    context = new K2Context();
  }

  /**
   * Tests installing a bad driver.
   */
  @Test public final void testInstallBadDriver() {
    K2Storage storage = new K2Storage(context);
    // Try to install a badly-implemented driver
    try {
      storage.installDriver(BadDriver.class);
      fail("Driver should not be installable.");
    } catch (StorageDriverException expected) {
      assertEquals(BadDriver.class, expected.getDriverClass());
    }    
    // Make sure that driver is NOT in the installed list
    assertEquals(0, storage.getInstalledDrivers().size());
  }
  
  // Test "data" for the above
  public static abstract class BadDriver extends MockDriver {
    private BadDriver() {}
  }

  /**
   * Tests installing one valid driver.
   */
  @Test public final void testInstallOneDriver() throws K2Exception {
    K2Storage storage = new K2Storage(context);
    
    // Make sure that no drivers exist initially
    assertEquals(0, storage.getInstalledDrivers().size());

    // Try to install
    InstalledDriver idriver = storage.installDriver(MockDriver.Normal.class);
    assertNotNull(idriver);
    assertEquals(MockDriver.Normal.class, idriver.getDriverClass());
    
    // Make sure that the driver is in the installed list
    List<InstalledDriver> drivers = storage.getInstalledDrivers();
    assertEquals(1, drivers.size());
    assertEquals(idriver, drivers.get(0));
    
    // Make sure that installing twice fails 
    assertNull(storage.installDriver(MockDriver.Normal.class));
    assertEquals(1, storage.getInstalledDrivers().size());
    
    // Make sure that installing a conflicting driver also fails
    // and does not change anything.
    // (conflicting = same identifier, but different class)
    assertNull(storage.installDriver(ConflictingDriver.class));
    drivers = storage.getInstalledDrivers();
    assertEquals(1, drivers.size());
    assertEquals(idriver, drivers.get(0));
  }
  
  // Test "data" for the above
  @DriverInfo(id="mock", name="Mock Store", version="1.0")
  public static class ConflictingDriver extends MockDriver.Normal {}
  
  /**
   * Tests installing several valid drivers.
   */
  @Test public final void testInstallSeveralDrivers() throws K2Exception {
    K2Storage storage = new K2Storage(context);
    
    // Install several drivers
    assertNotNull(storage.installDriver(MockDriver.Normal.class));
    assertEquals(1, storage.getInstalledDrivers().size());
    assertNotNull(storage.installDriver(MockDriver.ReadOnly.class));
    assertEquals(2, storage.getInstalledDrivers().size());
    assertNotNull(storage.installDriver(MockDriver.NoWrap.class));
    
    // Make sure that the drivers are all in the list, in order
    List<InstalledDriver> drivers = storage.getInstalledDrivers();
    assertEquals(3, drivers.size());
    assertEquals(MockDriver.Normal.class, drivers.get(0).getDriverClass());
    assertEquals(MockDriver.ReadOnly.class, drivers.get(1).getDriverClass());
    assertEquals(MockDriver.NoWrap.class, drivers.get(2).getDriverClass());
  }
  
  /**
   * Tests installing/uninstalling several drivers.
   */
  @Test public final void testDriverChurn() throws K2Exception {
    K2Storage storage = new K2Storage(context);
    
    // Install several drivers
    assertNotNull(storage.installDriver(MockDriver.NoWrap.class));
    assertNotNull(storage.installDriver(MockDriver.Normal.class));
    assertNotNull(storage.installDriver(MockDriver.ReadOnly.class));
    List<InstalledDriver> drivers = storage.getInstalledDrivers();
    
    // Uninstall middle driver
    assertTrue(storage.uninstallDriver(drivers.get(1).getId()));
    
    // Verify that initial list is UNCHANGED
    assertEquals(3, drivers.size());
    assertEquals(MockDriver.Normal.class, drivers.get(1).getDriverClass());

    // Check that new list is a different object
    List<InstalledDriver> newDrivers = storage.getInstalledDrivers();
    assertFalse(drivers == newDrivers);

    // Verify that new list is missing middle driver
    drivers = newDrivers;
    assertEquals(2, drivers.size());
    assertEquals(MockDriver.NoWrap.class, drivers.get(0).getDriverClass());
    assertEquals(MockDriver.ReadOnly.class, drivers.get(1).getDriverClass());

    // Install some other driver, then put back the one that was removed
    assertNotNull(storage.installDriver(MockDriver.AcceptAll.class));
    assertNotNull(storage.installDriver(MockDriver.Normal.class));
    
    // Check that the list is updated
    drivers = storage.getInstalledDrivers();
    assertEquals(4, drivers.size());
    assertEquals(MockDriver.NoWrap.class, drivers.get(0).getDriverClass());
    assertEquals(MockDriver.ReadOnly.class, drivers.get(1).getDriverClass());
    assertEquals(MockDriver.AcceptAll.class, drivers.get(2).getDriverClass());
    assertEquals(MockDriver.Normal.class, drivers.get(3).getDriverClass());
  }
  
  /**
   * Tests that open(String) rejects bad address strings and directs to
   * open(URI) on success.
   * 
   * If this passes, we can safely focus on testing open(URI).
   */
  @Test public void testOpenString() throws K2Exception {
    // Quick instrumentation of K2Storage to detect open(URI) call 
    final URI[] openAddress = { null };
    K2Storage storage = new K2Storage(context) {
      @Override
      public Store open(URI address)
          throws IllegalAddressException,
                 NoSuitableDriverException,
                 StoreException {
        openAddress[0] = address;
        return super.open(address);
      }
    };
    
    final String badAddress = "@_@:/ /%fF";
    final String expectedBad = "@_@:/%20/%fF"; 
    final String goodAddress = "file:///my/path%20/ 10%%";
    final String expectedGood = "file:///my/path%20/%2010%25%25";
    
    // Test that a bad address is rejected
    try {
      storage.open(badAddress).close();
      fail("Should not permit opening a bad string address.");
    } catch (IllegalAddressException expected) {
      assertEquals(expectedBad, expected.getAddress());
      assertEquals(
          IllegalAddressException.Reason.INVALID_URI, expected.getReason());
    }
    // open(URI) should NOT have been invoked
    assertNull(openAddress[0]);
    
    // Test that a good address gets to open(URI)
    try {
      storage.open(goodAddress).close();
      fail("Expected no suitable driver.");
    } catch (NoSuitableDriverException expected) {
      assertEquals(expectedGood, String.valueOf(expected.getAddress()));
    }
    assertEquals(expectedGood, String.valueOf(openAddress[0]));
  }
  
  /**
   * Tests open(URI) with an exact driver match for the address.
   */
  @Test public final void testOpenExactDriver() throws K2Exception {
    K2Storage storage = new K2Storage(context);
    URI exactAddress = URI.create("mock:///path/to/my/keys");
    URI fileAddress = URI.create("file:///path/to/my/keys");
    URI pathAddress = URI.create("/path/to/my/keys");
    assertNull(pathAddress.getScheme());
    
    // Verify that nothing can be opened without any drivers
    checkOpenFail(storage, exactAddress);
    checkOpenFail(storage, fileAddress);
    checkOpenFail(storage, pathAddress);
    
    // Install a driver that accepts all addresses.
    assertNotNull(storage.installDriver(MockDriver.AcceptAll.class));
    
    // Verify that all addresses go to this driver
    checkOpenSuccess(storage, exactAddress, MockDriver.AcceptAll.class);
    checkOpenSuccess(storage, fileAddress, MockDriver.AcceptAll.class);
    checkOpenSuccess(storage, pathAddress, MockDriver.AcceptAll.class);
    
    // Add new driver that matches "exactAddress" exactly.
    // This driver will be after the accept-all driver in search order.
    InstalledDriver exactDriver =
        storage.installDriver(MockDriver.Normal.class);
    assertNotNull(exactDriver);
    
    // Verify that (only) exactAddress now opens this driver
    checkOpenSuccess(storage, exactAddress, MockDriver.Normal.class);
    checkOpenSuccess(storage, fileAddress, MockDriver.AcceptAll.class);
    checkOpenSuccess(storage, pathAddress, MockDriver.AcceptAll.class);
    
    // Uninstall the driver
    assertTrue(storage.uninstallDriver(exactDriver.getId()));
    
    // Verify that there is no longer an exact match
    checkOpenSuccess(storage, exactAddress, MockDriver.AcceptAll.class);
  }

  /**
   * Tests open(URI) when searching among several drivers is required.
   */
  @Test public final void testOpenSearchDrivers() throws K2Exception {
    K2Storage storage = new K2Storage(context);
    URI k2Address = URI.create("k2:///root");
    URI fileAddress = URI.create("file:///path/to/my/keys");
    URI pathAddress = URI.create("/path/to/my/keys");

    // Install normal driver and a driver that accepts file addresses as well
    assertNotNull(storage.installDriver(MockDriver.Normal.class));
    InstalledDriver acceptFileDriver =
        storage.installDriver(MockDriver.AcceptFile.class);
    assertNotNull(acceptFileDriver);
    
    // K2 and path should trigger a search (and fail)
    checkOpenFail(storage, k2Address);
    checkOpenFail(storage, pathAddress);
    // The file address should be accepted after a brief search
    checkOpenSuccess(storage, fileAddress, MockDriver.AcceptFile.class);
    
    // Install an accept all driver
    assertNotNull(storage.installDriver(MockDriver.AcceptAll.class));

    // Now all should be successful, but the fileAddress should still
    // be with the same driver.
    checkOpenSuccess(storage, k2Address, MockDriver.AcceptAll.class);
    checkOpenSuccess(storage, pathAddress, MockDriver.AcceptAll.class);
    checkOpenSuccess(storage, fileAddress, MockDriver.AcceptFile.class);

    // Uninstall and reinstall AcceptFile driver (move to end of search list)
    assertTrue(storage.uninstallDriver(acceptFileDriver.getId()));
    acceptFileDriver = storage.installDriver(MockDriver.AcceptFile.class);
    assertNotNull(acceptFileDriver);

    // Now file address should point to AcceptAll with the
    // updated search order
    checkOpenSuccess(storage, fileAddress, MockDriver.AcceptAll.class);
  }
  
  /**
   * Tests that all methods throw up on a null argument.
   */
  @Test public final void testNullArguments() throws K2Exception {
    K2Storage storage = new K2Storage(context);
    try {
      storage.installDriver(null);
      fail("InstallDriver should not accept a null class.");
    } catch (NullPointerException expected) {
      assertEquals("driverClass", expected.getMessage());
    }
    try {
      storage.uninstallDriver(null);
      fail("UninstallDriver should not accept a null id.");
    } catch (NullPointerException expected) {
      assertEquals("id", expected.getMessage());
    }
    try {
      storage.open((String)null).close();
      fail("Open should not accept a null String.");
    } catch (NullPointerException expected) {
      assertEquals("address", expected.getMessage());
    }
    try {
      storage.open((URI)null).close();
      fail("Open should not accept a null URI.");
    } catch (NullPointerException expected) {
      assertEquals("address", expected.getMessage());
    }    
  }
  
  /**
   * Verifies that a store open succeeds for testOpenXXXDriver/s() tests.
   */
  private static void checkOpenSuccess(
      K2Storage storage, URI address, Class<? extends Driver> expectedDriver)
          throws K2Exception {
    Store store = storage.open(address);
    try {
      assertEquals(expectedDriver, store.getDriver().getClass());
    } finally {
      store.close();
    }
  }

  /**
   * Verifies that a store open fails for testOpenXXXDriver/s() tests.
   */
  private static void checkOpenFail(K2Storage storage, URI address)
      throws K2Exception {
    try {
      storage.open(address).close();
      fail("There should not be a matching driver.");
    } catch (NoSuitableDriverException expected) {
      assertEquals(address, expected.getAddress());
    }    
  }
}
