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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for an InstalledDriver.
 * <p>
 * Goal is to verify that the class will reject all badly-implemented drivers
 * and accept odd (but valid) driver implementations. 
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
    Class<? extends StoreDriver> driverClass = MockStoreDriver.class; 
    try {
      new InstalledDriver(null, driverClass);
      fail("Expected NullPointerException of context.");
    } catch (NullPointerException ex) {
      // Exception is expected
      assertEquals("context", ex.getMessage());
    }
  }
  
  /**
   * Tests rejection when the driver class to the constructor is null. 
   */
  @Test public final void testRejectNullDriverClass() throws K2Exception {
    try {
      new InstalledDriver(context, null);
      fail("Expected NullPointerException of driverClass.");
    } catch (NullPointerException ex) {
      // Exception is expected
      assertEquals("driverClass", ex.getMessage());
    }
  }
  
  /**
   * Tests successful verification and instantiation of a valid driver.
   */
  @Test public final void testAcceptValidDriver() throws K2Exception {
    Class<? extends StoreDriver> driverClass = MockStoreDriver.class; 
    InstalledDriver idriver = new InstalledDriver(context, driverClass);
    assertEquals(context, idriver.getContext());
    assertEquals(driverClass, idriver.getDriverClass());
    assertEquals("mock", idriver.getId());
    assertEquals("Mock Store", idriver.getName());
    assertEquals("1.0", idriver.getVersion());
    assertFalse(idriver.isReadOnly());
    assertTrue(idriver.isWrapSupported());
    assertEquals(driverClass.hashCode(), idriver.hashCode());
    
    StoreDriver driver = idriver.instantiate();
    assertTrue(driverClass.isInstance(driver));
    assertEquals(context, ((MockStoreDriver)driver).context);
  }

  /**
   * Tests rejection of an abstract driver. 
   */
  @Test public final void testRejectAbstractDriver() {
    Class<? extends StoreDriver> driverClass = AbstractDriver.class; 
    try {
      new InstalledDriver(context, driverClass);
      fail("Driver classes cannot be abstract.");
    } catch (StoreDriverException ex) {
      // Exception is expected
      assertEquals(driverClass, ex.getDriverClass());
      assertEquals(StoreDriverException.Reason.INSTANTIATE_FAIL,
          ex.getReason());
    }
  }
  
  @StoreDriverInfo(id="mock", name="Abstract Driver", version="1.0",
      readOnly=false, wrapSupported=true)
  public static abstract class AbstractDriver extends MockStoreDriver {
    public AbstractDriver() {}
  }
  
  /**
   * Tests acceptance of a private driver with a package-protected constructor.
   * (Yes, this works.)
   */
  @Test public final void testAcceptPrivateDriver() throws K2Exception {
    Class<? extends StoreDriver> driverClass = PrivateDriver.class; 
    StoreDriver driver =
        new InstalledDriver(context, driverClass).instantiate();
    assertTrue(driverClass.isInstance(driver));
  }

  @StoreDriverInfo(id="mock", name="Private Driver", version="1.0",
      readOnly=false, wrapSupported=true)
  private static class PrivateDriver extends MockStoreDriver {
    @SuppressWarnings("unused")
    PrivateDriver() {}
  }

  /**
   * Tests rejection of a driver with a private constructor. 
   */
  @Test public final void testRejectPrivateConstructor() {
    Class<? extends StoreDriver> driverClass = PrivateConstructorDriver.class; 
    try {
      new InstalledDriver(context, driverClass);
      fail("Driver classes cannot have a private constructor.");
    } catch (StoreDriverException ex) {
      // Exception is expected
      assertEquals(driverClass, ex.getDriverClass());
      assertEquals(StoreDriverException.Reason.INSTANTIATE_FAIL,
          ex.getReason());
    }
  }
  
  @StoreDriverInfo(id="mock", name="Private Constructor Driver", version="1.0",
      readOnly=false, wrapSupported=true)
  public static class PrivateConstructorDriver extends MockStoreDriver {
    private PrivateConstructorDriver() {}
  }
 
  /**
   * Tests rejection of a driver with a constructor that throws illegal
   * throwables. 
   */
  @Test public final void testRejectConstructorWithBadThrowables() {
    Class<? extends StoreDriver> driverClass =
        ConstructorWithBadThrowablesDriver.class; 
    try {
      new InstalledDriver(context, driverClass);
      fail("Drivers with constructors throwing throwables other than Error "
          + "and RuntimeException are invalid.");
    } catch (StoreDriverException ex) {
      // Exception is expected
      assertEquals(driverClass, ex.getDriverClass());
      assertEquals(StoreDriverException.Reason.ILLEGAL_THROWS,
          ex.getReason());
    }
  }
  
  @StoreDriverInfo(id="mock", name="Constructor with Bad Throwables Driver",
      version="1.0", readOnly=false, wrapSupported=true)
  public static class ConstructorWithBadThrowablesDriver
      extends MockStoreDriver {
    public ConstructorWithBadThrowablesDriver()
        throws Exception, Throwable {
    }
  }
  
  /**
   * Test acceptance of a driver with a constructor that throws entirely legal
   * throwables.
   */
  @Test public final void testAcceptConstructorWithLegalThrowables()
      throws K2Exception {
    Class<? extends StoreDriver> driverClass =
        ConstructorWithLegalThrowablesDriver.class; 
    StoreDriver driver =
        new InstalledDriver(context, driverClass).instantiate();
    assertTrue(driverClass.isInstance(driver));
  }
  
  @StoreDriverInfo(id="mock", name="Constructor with Legal Throwables Driver",
      version="1.0", readOnly=true, wrapSupported=true)
  public static class ConstructorWithLegalThrowablesDriver
      extends MockStoreDriver {
    public ConstructorWithLegalThrowablesDriver()
        throws Error, RuntimeException {
    }
  }

  /**
   * Tests rejection of a driver without the meta-data annotation.
   */
  @Test public final void testRejectNoAnnotation() {
    Class<? extends StoreDriver> driverClass = NoAnnotationDriver.class; 
    try {
      new InstalledDriver(context, driverClass);
      fail("Driver classes must have the StoreDriverInfo annotation.");
    } catch (StoreDriverException ex) {
      // Exception is expected
      assertEquals(driverClass, ex.getDriverClass());
      assertEquals(StoreDriverException.Reason.NO_METADATA, ex.getReason());
    }
  }
  
  public static class NoAnnotationDriver extends MockStoreDriver {
    public NoAnnotationDriver() {}    
  }
  
  /**
   * Tests rejection of a driver with an empty identifier.
   */
  @Test public final void testRejectEmptyIdentifier() {
    Class<? extends StoreDriver> driverClass = EmptyIdentifierDriver.class; 
    try {
      new InstalledDriver(context, driverClass);
      fail("Driver classes cannot have an empty identifier.");
    } catch (StoreDriverException ex) {
      // Exception is expected
      assertEquals(driverClass, ex.getDriverClass());
      assertEquals(StoreDriverException.Reason.ILLEGAL_ID, ex.getReason());
    }
  }
  
  @StoreDriverInfo(id="", name="Empty Identifier Driver", version="1.0",
      readOnly=false, wrapSupported=true)
  public static class EmptyIdentifierDriver extends MockStoreDriver {
    public EmptyIdentifierDriver() {}    
  }
  
  /**
   * Tests rejection of a driver with an illegal identifier.
   */
  @Test public final void testRejectBadIdentifier() {
    Class<? extends StoreDriver> driverClass = BadIdentifierDriver.class; 
    try {
      new InstalledDriver(context, driverClass);
      fail("Driver classes must have a legal identifier.");
    } catch (StoreDriverException ex) {
      // Exception is expected
      assertEquals(driverClass, ex.getDriverClass());
      assertEquals(StoreDriverException.Reason.ILLEGAL_ID, ex.getReason());
    }
  }
  
  @StoreDriverInfo(id="0b:@_d I/D", name="Bad Identifier Driver", version="1.0",
      readOnly=false, wrapSupported=true)
  public static class BadIdentifierDriver extends MockStoreDriver {
    public BadIdentifierDriver() {}
  }
  
  /**
   * Tests acceptance of a driver with a complex but legal identifier.
   */
  @Test public final void testAcceptComplexIdentifier() throws K2Exception {
    Class<? extends StoreDriver> driverClass = ComplexIdentifierDriver.class; 
    InstalledDriver idriver = new InstalledDriver(context, driverClass);
    assertEquals(context, idriver.getContext());
    assertEquals(driverClass, idriver.getDriverClass());
    assertEquals("c0m-p13x+id.", idriver.getId());
    assertEquals("Complex Identifier Driver", idriver.getName());
    assertEquals("1.0a", idriver.getVersion());
    assertTrue(idriver.isReadOnly());
    assertTrue(idriver.isWrapSupported());
    assertEquals(driverClass.hashCode(), idriver.hashCode());

    StoreDriver driver = idriver.instantiate();
    assertTrue(driverClass.isInstance(driver));
    assertEquals(context, ((MockStoreDriver)driver).context);
  }
  
  @StoreDriverInfo(id="c0m-p13x+id.", name="Complex Identifier Driver",
      version="1.0a", wrapSupported=true, readOnly=true)
  public static class ComplexIdentifierDriver extends MockStoreDriver {
    public ComplexIdentifierDriver() {}
  }
}
