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

import com.google.k2crypto.K2Context;
import com.google.k2crypto.storage.driver.Driver;
import com.google.k2crypto.storage.driver.DriverInfo;
import com.google.k2crypto.storage.driver.ReadableDriver;
import com.google.k2crypto.storage.driver.WrappingDriver;
import com.google.k2crypto.storage.driver.WritableDriver;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.regex.Pattern;

/**
 * A driver that has been installed into the storage system.
 * 
 * <p>This class is thread-safe.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public class InstalledDriver {
  
  // Regex matching a valid URI scheme.
  // (Same as http://tools.ietf.org/html/rfc3986#section-3.1,
  //  except we do not accept upper-case.)
  private static final Pattern LEGAL_ID =
      Pattern.compile("^[a-z][a-z0-9\\+\\-\\.]*$");
  
  // Context for the current K2 session
  private final K2Context context;
  
  // Class of the driver implementation.
  private final Class<? extends Driver> driverClass;
  
  // Constructor obtained from the driver class
  private final Constructor<? extends Driver> constructor;
  
  // Info annotation obtained from the driver class
  private final DriverInfo info;

  // Driver capabilities, derived from the interfaces implemented
  private final boolean canRead;
  private final boolean canWrite;
  private final boolean wrapSupported;
  
  /**
   * Constructs an installed driver from a class and verifies that it conforms
   * to the expected structure.
   * 
   * @param context Context for the K2 session.
   * @param driverClass Class of the driver implementation to install.
   * 
   * @throws StorageDriverException if the driver does not conform.
   */
  InstalledDriver(K2Context context, Class<? extends Driver> driverClass)
      throws StorageDriverException {
    if (context == null) {
      throw new NullPointerException("context");
    } else if (driverClass == null) {
      throw new NullPointerException("driverClass");
    }
    
    this.context = context;
    this.driverClass = driverClass;
    
    // Determine what the driver can do
    this.canRead = ReadableDriver.class.isAssignableFrom(driverClass);
    this.canWrite = WritableDriver.class.isAssignableFrom(driverClass);
    this.wrapSupported = WrappingDriver.class.isAssignableFrom(driverClass);
    
    if (!canRead && !canWrite) {
      // A driver that can neither read nor write is literally useless
      throw new StorageDriverException(
          driverClass, StorageDriverException.Reason.USELESS);      
    }

    try {
      // Check for a constructor with no arguments
      constructor = driverClass.getDeclaredConstructor();
      // Constructor can only throw Errors or RuntimeExceptions
      for (Class<?> exClass : constructor.getExceptionTypes()) {
        if (!RuntimeException.class.isAssignableFrom(exClass)
            && !Error.class.isAssignableFrom(exClass)) {
          throw new StorageDriverException(
              driverClass, StorageDriverException.Reason.ILLEGAL_THROWS);
        }
      }
      // Try to instantiate the driver (should work if driver is accessible)
      constructor.newInstance();
      
    } catch (NoSuchMethodException ex) {
      // Constructor not found
      throw new StorageDriverException(
          driverClass, StorageDriverException.Reason.NO_CONSTRUCTOR);        
    } catch (ReflectiveOperationException ex) {
      // Instantiation failed
      throw new StorageDriverException(
          driverClass, StorageDriverException.Reason.INSTANTIATE_FAIL);
    }

    // Check that annotation is present
    info = driverClass.getAnnotation(DriverInfo.class);
    if (info == null) {
      throw new StorageDriverException(
          driverClass, StorageDriverException.Reason.NO_METADATA);
    }
    
    // Check that driver identifier is legal
    if (!LEGAL_ID.matcher(info.id()).matches()) {
      throw new StorageDriverException(
          driverClass, StorageDriverException.Reason.ILLEGAL_ID);        
    }
  }
  
  /**
   * Instantiates a new store (driver) from the driver installation.
   */
  Driver instantiate() {
    try {
      // Use reflection to instantiate the driver
      Driver driver = constructor.newInstance();
      driver.initialize(context);
      return driver;
    } catch (InvocationTargetException ex) {
      Throwable t = ex.getCause();
      // Re-throw throwables that do not need an explicit catch. (This should
      // not actually happen unless the driver has a flaky constructor.)
      if (t instanceof Error) {
        throw (Error)t;
      } else if (t instanceof RuntimeException) {
        throw (RuntimeException)t;
      } else {
        // This should not happen, owing to construction-time checks.
        throw new AssertionError("Should not happen!", t);
      }
    } catch (ReflectiveOperationException ex) {
      // Should not happen because we test instantiate in the constructor...
      throw new AssertionError("Should not happen!", ex);
    }
  }
  
  /**
   * Returns the context used when the driver was installed.
   */
  K2Context getContext() {
    return context;
  }
  
  /**
   * Returns the driver class.
   */
  public Class<? extends Driver> getDriverClass() {
    return driverClass;
  }
  
  /**
   * Returns the identifier of the driver.
   */
  public String getId() {
    return info.id();
  }
  
  /**
   * Returns the descriptive name of the driver.
   */
  public String getName() {
    return info.name();
  }
  
  /**
   * Returns the version of the driver.
   */
  public String getVersion() {
    return info.version();
  }
  
  /**
   * Returns {@code true} if the driver can read keys, {@code false} otherwise. 
   */
  public boolean canRead() {
    return canRead;
  }
  
  /**
   * Returns whether the driver can only read keys and not write them.
   */
  public boolean isReadOnly() {
    return canRead && !canWrite;
  }
  
  /**
   * Returns {@code true} if the driver can write keys, {@code false} otherwise. 
   */
  public boolean canWrite() {
    return canWrite;
  }
  
  /**
   * Returns whether the driver can only write keys and not read them.
   */
  public boolean isWriteOnly() {
    return canWrite && !canRead;
  }
  
  /**
   * Returns whether the driver supports wrapped (encrypted) keys.
   */
  public boolean isWrapSupported() {
    return wrapSupported;
  }
  
  /**
   * Returns the hash-code for the driver, which is the hash of the driver
   * class.
   */
  @Override
  public int hashCode() {
    return driverClass.hashCode();
  }
  
  /**
   * Tests the driver for equality with an object.
   * 
   * @param obj Object to compare to.
   * 
   * @return {@code true} if, and only if, the object is also an
   *         InstalledDriver and it has the same driver class and context as
   *         this one. 
   */
  @Override
  public boolean equals(Object obj) {
    if (obj instanceof InstalledDriver) {
      InstalledDriver other = (InstalledDriver)obj;
      return other.driverClass.equals(driverClass)
          && other.context.equals(context);
    }
    return false;
  }
  
  /**
   * @see Object#toString()
   */
  @Override
  public String toString() {
    return "[" + getId() + "/" + driverClass.getName() + "] "
        + getName() + " " + getVersion();
  }
}
