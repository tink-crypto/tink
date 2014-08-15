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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.k2crypto.K2Context;
import com.google.k2crypto.K2Exception;
import com.google.k2crypto.Key;
import com.google.k2crypto.storage.driver.Driver;
import com.google.k2crypto.storage.driver.DriverInfo;
import com.google.k2crypto.storage.driver.ReadableDriver;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.net.URI;

/**
 * Unit tests for an InstalledDriver.
 * 
 * <p>Goal is to verify that the class will reject all badly-implemented
 * drivers and accept odd (but valid) driver implementations. 
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
@RunWith(JUnit4.class)
public class InstalledDriverTest {
  
  private K2Context context = null;
 
  /**
   * Creates a context for the tests.
   */
  @Before public final void setUp() {
    context = new K2Context();
  }

  /**
   * Tests rejection when the context to the constructor is null. 
   */
  @Test public final void testRejectNullContext() throws K2Exception {
    Class<? extends Driver> driverClass = MockDriver.class; 
    try {
      new InstalledDriver(null, driverClass);
      fail("Expected NullPointerException of context.");
    } catch (NullPointerException expected) {
      assertEquals("context", expected.getMessage());
    }
  }
  
  /**
   * Tests rejection when the driver class to the constructor is null. 
   */
  @Test public final void testRejectNullDriverClass() throws K2Exception {
    try {
      new InstalledDriver(context, null);
      fail("Expected NullPointerException of driverClass.");
    } catch (NullPointerException expected) {
      assertEquals("driverClass", expected.getMessage());
    }
  }
  
  /**
   * Utility to verify that a driver class is accepted. 
   * 
   * @param driverClass Class of the driver.
   * 
   * @return the InstalledDriver that accepted the implementation,
   *         for further checking.
   *         
   * @throws StorageDriverException if the driver is rejected.
   */
  private InstalledDriver checkAcceptInstallation(
      Class<? extends Driver> driverClass) throws StorageDriverException {
    InstalledDriver idriver = new InstalledDriver(context, driverClass);
    assertEquals(context, idriver.getContext());
    assertEquals(driverClass, idriver.getDriverClass());
    assertEquals(driverClass.hashCode(), idriver.hashCode());
    Driver driver = idriver.instantiate();
    assertTrue(driverClass.isInstance(driver));
    assertEquals(context, ((MockDriver)driver).context);
    return idriver;
  }
  
  /**
   * Utility to verify that a driver class is rejected for the specified reason. 
   * 
   * @param driverClass Driver class to check.
   * @param reason Reason for the rejection.
   * @param failMessage Assertion message used if the driver is NOT rejected. 
   */
  private void checkRejectInstallation(
      Class<? extends Driver> driverClass,
      StorageDriverException.Reason reason,
      String failMessage) {
    try {
      new InstalledDriver(context, driverClass);
      fail(failMessage);
    } catch (StorageDriverException expected) {
      assertEquals(driverClass, expected.getDriverClass());
      assertEquals(reason, expected.getReason());
    }
  }
  
  /**
   * Tests rejection of a driver that is neither capable of reading nor writing.
   */
  @Test public final void testRejectUselessDriver() {
    checkRejectInstallation(
        MockDriver.class,
        StorageDriverException.Reason.USELESS,
        "Drivers that are useless should be rejected.");
  }

  /**
   * Tests acceptance of a normal (read/write/wrap-capable) driver.
   */
  @Test public final void testAcceptNormalDriver() throws K2Exception {
    InstalledDriver idriver =
        checkAcceptInstallation(MockDriver.Normal.class); 
    assertEquals("mock", idriver.getId());
    assertEquals("Mock Driver", idriver.getName());
    assertEquals("1.0", idriver.getVersion());
    assertTrue(idriver.canRead());
    assertFalse(idriver.isReadOnly());
    assertTrue(idriver.canWrite());
    assertFalse(idriver.isWriteOnly());
    assertTrue(idriver.isWrapSupported());
  }

  /**
   * Tests acceptance of a read-only driver.
   */
  @Test public final void testAcceptReadOnlyDriver() throws K2Exception {
    InstalledDriver idriver =
        checkAcceptInstallation(MockDriver.ReadOnly.class); 
    assertEquals("mock-ro", idriver.getId());
    assertEquals("Read-Only Mock Driver", idriver.getName());
    assertEquals("2.0", idriver.getVersion());
    assertTrue(idriver.canRead());
    assertTrue(idriver.isReadOnly());
    assertFalse(idriver.canWrite());
    assertFalse(idriver.isWriteOnly());
    assertTrue(idriver.isWrapSupported());
  }
  
  /**
   * Tests acceptance of a write-only driver.
   */
  @Test public final void testAcceptWriteOnlyDriver() throws K2Exception {
    InstalledDriver idriver =
        checkAcceptInstallation(MockDriver.WriteOnly.class); 
    assertEquals("mock-wo", idriver.getId());
    assertEquals("Write-Only Mock Driver", idriver.getName());
    assertEquals("3.0", idriver.getVersion());
    assertFalse(idriver.canRead());
    assertFalse(idriver.isReadOnly());
    assertTrue(idriver.canWrite());
    assertTrue(idriver.isWriteOnly());
    assertTrue(idriver.isWrapSupported());
  }
  
  /**
   * Tests acceptance of a no-wrap driver.
   */
  @Test public final void testAcceptNoWrapDriver() throws K2Exception {
    InstalledDriver idriver =
        checkAcceptInstallation(MockDriver.NoWrap.class); 
    assertEquals("mock-nw", idriver.getId());
    assertEquals("No-Wrap Mock Driver", idriver.getName());
    assertEquals("4.0", idriver.getVersion());
    assertTrue(idriver.canRead());
    assertFalse(idriver.isReadOnly());
    assertTrue(idriver.canWrite());
    assertFalse(idriver.isWriteOnly());
    assertFalse(idriver.isWrapSupported());
  }
  
  /**
   * Tests rejection of a driver without a zero-argument constructor. 
   */
  @Test public final void testRejectNoConstructorDriver() {
    checkRejectInstallation(
        NoConstructorDriver.class,
        StorageDriverException.Reason.NO_CONSTRUCTOR,
        "Drivers without a zero-argument constructor should be rejected.");
  }
  
  // Test "data" for the above
  @DriverInfo(id = "mock", name = "No Constructor Driver", version = "1.0")
  public static class NoConstructorDriver extends MockDriver.Normal {
    public NoConstructorDriver(@SuppressWarnings("unused") Object obj) {}
  }
  
  /**
   * Tests rejection of an abstract driver. 
   */
  @Test public final void testRejectAbstractDriver() {
    checkRejectInstallation(
        AbstractDriver.class,
        StorageDriverException.Reason.INSTANTIATE_FAIL,
        "Abstract drivers should be rejected.");
  }
  
  // Test "data" for the above
  @DriverInfo(id = "mock", name = "Abstract Driver", version = "1.0")
  public static abstract class AbstractDriver extends MockDriver.Normal {
    public AbstractDriver() {}
  }
  
  /**
   * Tests acceptance of a private driver with a package-protected constructor.
   * (Yes, this works.)
   */
  @Test public final void testAcceptPrivateDriver() throws K2Exception {
    InstalledDriver idriver =
        checkAcceptInstallation(PrivateDriver.class);
    assertEquals("priv", idriver.getId());      
    assertEquals("Private Driver", idriver.getName());
    assertEquals("1.0.0", idriver.getVersion());
  }

  // Test "data" for the above
  @DriverInfo(id = "priv", name = "Private Driver", version = "1.0.0")
  private static class PrivateDriver extends MockDriver.Normal {
    @SuppressWarnings("unused") PrivateDriver() {}
  }

  /**
   * Tests rejection of a driver with a private constructor. 
   */
  @Test public final void testRejectPrivateConstructor() {
    checkRejectInstallation(
        PrivateConstructorDriver.class,
        StorageDriverException.Reason.INSTANTIATE_FAIL,
        "Drivers with private constructors should be rejected.");
  }
  
  // Test "data" for the above
  @DriverInfo(id = "mock", name = "Private Constructor Driver", version = "1.0")
  public static class PrivateConstructorDriver extends MockDriver.Normal {
    private PrivateConstructorDriver() {}
  }
 
  /**
   * Tests rejection of a driver with a constructor that throws illegal
   * throwables. 
   */
  @Test public final void testRejectConstructorWithBadThrowables() {
    checkRejectInstallation(
        ConstructorWithBadThrowablesDriver.class,
        StorageDriverException.Reason.ILLEGAL_THROWS,
        "Drivers with constructors throwing throwables other than Error "
            + "and RuntimeException should be rejected.");
  }
  
  // Test "data" for the above
  @DriverInfo(
      id = "mock",
      name = "Constructor with Bad Throwables Driver",
      version = "1.0")
  public static class ConstructorWithBadThrowablesDriver
      extends MockDriver.Normal {
    public ConstructorWithBadThrowablesDriver() throws Exception, Throwable {}
  }
  
  /**
   * Test acceptance of a driver with a constructor that throws entirely legal
   * throwables.
   */
  @Test public final void testAcceptConstructorWithLegalThrowables()
      throws K2Exception {
    InstalledDriver idriver =
        checkAcceptInstallation(ConstructorWithLegalThrowablesDriver.class);
    assertEquals("legalcon", idriver.getId());      
    assertEquals("Constructor with Legal Throwables Driver", idriver.getName());
    assertEquals("0.1", idriver.getVersion());
  }
  
  // Test "data" for the above
  @DriverInfo(
      id = "legalcon",
      name = "Constructor with Legal Throwables Driver",
      version = "0.1")
  public static class ConstructorWithLegalThrowablesDriver
      extends MockDriver.Normal {
    public ConstructorWithLegalThrowablesDriver()
        throws Error, RuntimeException {}
  }

  /**
   * Tests rejection of a driver without the meta-data annotation.
   */
  @Test public final void testRejectNoAnnotation() {
    checkRejectInstallation(
        NoAnnotationDriver.class,
        StorageDriverException.Reason.NO_METADATA,
        "Drivers without the StoreDriverInfo annotation should be rejected.");
  }
  
  // Test "data" for the above
  public static class NoAnnotationDriver implements Driver, ReadableDriver {
    public NoAnnotationDriver() {}
    public void initialize(K2Context context) {}
    public URI open(URI address) { return null; }
    public void close() {}
    public boolean isEmpty() { return false; }
    public Key load() { return null; }
  }
  
  /**
   * Tests rejection of a driver with an empty identifier.
   */
  @Test public final void testRejectEmptyIdentifier() {
    checkRejectInstallation(
        EmptyIdentifierDriver.class,
        StorageDriverException.Reason.ILLEGAL_ID,
        "Drivers with empty identifiers should be rejected.");
  }
  
  // Test "data" for the above
  @DriverInfo(id = "", name = "Empty Identifier Driver", version = "1.0")
  public static class EmptyIdentifierDriver extends MockDriver.Normal {
    public EmptyIdentifierDriver() {}    
  }
  
  /**
   * Tests rejection of a driver with an illegal identifier.
   */
  @Test public final void testRejectBadIdentifier() {
    checkRejectInstallation(
        BadIdentifierDriver.class,
        StorageDriverException.Reason.ILLEGAL_ID,
        "Drivers with illegal identifiers should be rejected.");
  }
  
  // Test "data" for the above
  @DriverInfo(
      id = "0b:@_d I/D",
      name = "Bad Identifier Driver",
      version = "1.0")
  public static class BadIdentifierDriver extends MockDriver.Normal {
    public BadIdentifierDriver() {}
  }
  
  /**
   * Tests acceptance of a driver with a complex but legal identifier.
   */
  @Test public final void testAcceptComplexIdentifier() throws K2Exception {
    InstalledDriver idriver =
        checkAcceptInstallation(ComplexIdentifierDriver.class); 
    assertEquals("c0m-p13x+id.", idriver.getId());      
    assertEquals("Complex Identifier Driver", idriver.getName());
    assertEquals("1.0a", idriver.getVersion());
  }
  
  // Test "data" for the above
  @DriverInfo(
      id = "c0m-p13x+id.",
      name = "Complex Identifier Driver",
      version = "1.0a")
  public static class ComplexIdentifierDriver extends MockDriver.Normal {
    public ComplexIdentifierDriver() {}
  }
}
