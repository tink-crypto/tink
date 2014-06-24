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
import com.google.k2crypto.i18n.K2Strings;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.util.regex.Pattern;
import java.net.URI;

/**
 * Driver after it has been installed into the storage system.
 * 
 * @author darylseah@google.com (Daryl Seah)
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
  private final Class<? extends StoreDriver> driverClass;
  
  // Constructor obtained from the driver class
  private final Constructor<? extends StoreDriver> constructor;
  
  // Info annotation obtained from the driver class
  private final StoreDriverInfo info;
  
  /**
   * Constructs an installed driver from a class and verifies that it conforms
   * to the expected structure.
   * 
   * @param context Context for the K2 session.
   * @param driverClass Class of the driver implementation to install.
   * 
   * @throws StoreDriverException if the driver does not conform.
   */
  InstalledDriver(K2Context context, Class<? extends StoreDriver> driverClass)
      throws StoreDriverException {
    if (context == null) {
      throw new NullPointerException("context");
    } else if (driverClass == null) {
      throw new NullPointerException("driverClass");
    }
    
    this.context = context;
    this.driverClass = driverClass;
    K2Strings strings = context.getStrings();

    // Check that class is non-abstract
    if (Modifier.isAbstract(driverClass.getModifiers())) {
      throw new StoreDriverException(driverClass,
          strings.get("storage.driver.abstract"));        
    }
    
    // Check that class (and enclosing classes) are public
    for (Class<?> cl = driverClass; cl != null; cl = cl.getEnclosingClass()) {
      if (!Modifier.isPublic(cl.getModifiers())) {
        throw new StoreDriverException(driverClass,
            strings.get("storage.driver.nonpublic"));
      } 
    } 
    
    // Check for a public constructor with a valid signature
    try {
      constructor = driverClass.getConstructor(K2Context.class, URI.class);
      
      // Constructor can only throw errors, runtime or IllegalAddressExceptions
      for (Class<?> exClass : constructor.getExceptionTypes()) {
        if (!RuntimeException.class.isAssignableFrom(exClass) &&
              !Error.class.isAssignableFrom(exClass) &&
              !IllegalAddressException.class.isAssignableFrom(exClass)) {
          throw new StoreDriverException(driverClass,
              strings.get("storage.driver.constructor_throwsbad"));
        }
      }
    } catch (NoSuchMethodException ex) {
      throw new StoreDriverException(driverClass,
          strings.get("storage.driver.constructor_missing"));        
    }

    // Check that annotation is present
    info = driverClass.getAnnotation(StoreDriverInfo.class);
    if (info == null) {
      throw new StoreDriverException(driverClass,
          strings.get("storage.driver.metadata_missing"));
    }
    
    // Check that driver identifier is legal
    if (!LEGAL_ID.matcher(info.id()).matches()) {
      throw new StoreDriverException(driverClass,
          strings.get("storage.driver.id_illegal"));        
    }
  }
  
  /**
   * Instantiates a new store (driver) from the driver installation.
   * 
   * @param address Address to pass to the driver.
   * 
   * @throws IllegalAddressException if the driver cannot accept the address.
   */
  StoreDriver instantiate(URI address) throws IllegalAddressException {
    if (address == null) {
      throw new NullPointerException("address");
    }
    try {
      // Use reflection to instantiate the driver
      return constructor.newInstance(context, address);
    } catch (InvocationTargetException ex) {
      Throwable t = ex.getCause();
      // Re-throw permissible throwables
      if (t instanceof Error) {
        throw (Error)t;
      } else if (t instanceof RuntimeException) {
        throw (RuntimeException)t;
      } else if (t instanceof IllegalAddressException) {
        throw (IllegalAddressException)t;
      } else {
        // This should not happen, owing to construction-time checks.
        throw new AssertionError(context
            .getStrings().get("misc.unexpected"), t);
      }
    } catch (IllegalAccessException ex) {
      // Should not happen because we check that the constructor is public... 
      throw new AssertionError(context
          .getStrings().get("misc.unexpected"), ex);
    } catch (InstantiationException ex) {
      // Should only occur if abstract class, which we also check for...
      throw new AssertionError(context
          .getStrings().get("misc.unexpected"), ex);
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
  public Class<? extends StoreDriver> getDriverClass() {
    return constructor.getDeclaringClass();
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
   * Returns whether the driver can only read keys and not write them.
   */
  public boolean isReadOnly() {
    return info.readOnly();
  }
  
  /**
   * Returns whether the driver supports wrapped (encrypted) keys.
   */
  public boolean isWrapSupported() {
    return info.wrapSupported();
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
      return other.driverClass.equals(driverClass) &&
          other.context.equals(context);
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
