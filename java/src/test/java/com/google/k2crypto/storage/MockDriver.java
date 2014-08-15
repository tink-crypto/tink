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

import static org.junit.Assert.fail;

import com.google.k2crypto.Key;
import com.google.k2crypto.K2Context;
import com.google.k2crypto.storage.driver.Driver;
import com.google.k2crypto.storage.driver.DriverInfo;
import com.google.k2crypto.storage.driver.ReadableDriver;
import com.google.k2crypto.storage.driver.WrappingDriver;
import com.google.k2crypto.storage.driver.WritableDriver;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Mock implementation of a storage driver. The mock super-class implements all
 * driver capabilities, but does not declare them. This is so that sub-classes
 * can selectively declare what capabilities they want the mock to expose. 
 * Also, by default, the mock will reject addresses that have a schemes that
 * do not match its identifier.
 * 
 * <p>The mock will raise assertion errors if it is used in a manner
 * that violates expected {@link Store} behavior.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
@DriverInfo(id = "mock", name = "Mock Driver", version = "1.0")
public abstract class MockDriver implements Driver {
  // All variables are package-protected for easy inspection.
  
  K2Context context;
  URI address;
  
  // Wrap key specified through wrapWith()
  Key wrapKey = null;
  
  // Emulated key storage, with associated wrapping at save() time.
  Key storedKey = null;
  Key storedKeyWrapper = null;
  
  // Whether these methods have been called
  boolean initCalled = false;
  boolean openCalled = false;
  boolean closeCalled = false;
  
  // Call counts to the other methods
  int wrapWithCalls = 0;
  int isWrappingCalls = 0;
  int isEmptyCalls = 0;
  int saveCalls = 0;
  int loadCalls = 0;
  int eraseCalls = 0;
  
  /**
   * Returns the meta-data annotated on the driver class.
   */
  DriverInfo getInfo() {
    DriverInfo info = getClass().getAnnotation(DriverInfo.class);
    if (info == null) {
      fail("There should be an annotation.");
    }
    return info;
  }
  
  /**
   * @see Driver#initialize(K2Context)
   */
  public void initialize(K2Context context) {
    boolean prevInitCalled = initCalled;
    initCalled = true;
    if (context == null) {
      fail("Context passed to the driver should not be null.");
    } else if (prevInitCalled) {
      fail("Driver should not be initialized twice.");
    }
    this.context = context;
  }

  /**
   * @see Driver#open(java.net.URI)
   */
  public URI open(URI address) throws IllegalAddressException, StoreException {
    boolean prevOpenCalled = openCalled;
    openCalled = true;
    if (address == null) {
      fail("Address passed to the driver should not be null.");
    } else if (prevOpenCalled) {
      fail("Driver should not be opened twice.");
    } else if (closeCalled) {
      fail("Driver should not be opened after close.");
    }
    
    if (!getInfo().id().equalsIgnoreCase(address.getScheme())) {
      // Reject foreign schemes as default behavior.
      // (This is not necessarily true for all driver implementations.)
      throw new IllegalAddressException(
          address, IllegalAddressException.Reason.INVALID_SCHEME, null);
    }
    
    this.address = address;
    return address;
  }

  /**
   * @see Driver#close()
   */
  public void close() {
    boolean prevCloseCalled = closeCalled;
    closeCalled = true;
    if (prevCloseCalled) {
      fail("Driver should not be closed twice.");
    }
  }

  /**
   * Checks that the driver is opened and not closed.
   */
  protected void checkOpen() {
    if (!openCalled) {
      fail("Driver has not been opened.");
    } else if (closeCalled) {
      fail("Driver has been closed.");
    }
  }
  
  /**
   * @see WrappingDriver#wrapWith(Key)
   */
  public void wrapWith(Key key) {
    ++wrapWithCalls;
    checkOpen();
    wrapKey = key;
  }

  /**
   * @see WrappingDriver#isWrapping()
   */
  public boolean isWrapping() {
    ++isWrappingCalls;
    checkOpen();
    return wrapKey != null;
  }

  /**
   * @see ReadableDriver#isEmpty()
   */
  public boolean isEmpty() {
    ++isEmptyCalls;
    checkOpen();
    return storedKey == null;
  }

  /**
   * @see WritableDriver#save(Key)
   */
  public void save(Key key) {
    ++saveCalls;
    if (key == null) {
      fail("Key to save should never be null.");
    }
    checkOpen();
    storedKey = key;
    storedKeyWrapper = wrapKey;
  }

  /**
   * @see ReadableDriver#load()
   */
  public Key load() throws StoreException {
    ++loadCalls;
    checkOpen();
    if (storedKey != null) {
      if (storedKeyWrapper == null) {
        if (wrapKey != null) {
          throw new StoreIOException(
              StoreIOException.Reason.WRAP_KEY_UNNECESSARY);                  
        }
      } else if (!storedKeyWrapper.equals(wrapKey)) {
        throw new StoreIOException(wrapKey == null
            ? StoreIOException.Reason.WRAP_KEY_REQUIRED
            : StoreIOException.Reason.WRAP_KEY_WRONG);        
      }
      return storedKey;
    }
    return null;
  }

  /**
   * @see WritableDriver#erase()
   */
  public boolean erase() {
    ++eraseCalls;
    checkOpen();
    Key erasedKey = storedKey;
    storedKey = null;
    storedKeyWrapper = null;
    return erasedKey != null;
  }
  
  /**
   * A normal full-capability version of the mock driver. 
   */
  public static class Normal extends MockDriver
      implements ReadableDriver, WritableDriver, WrappingDriver {
  }

  /**
   * A read-only version of the mock driver. 
   */
  @DriverInfo(id = "mock-ro", name = "Read-Only Mock Driver", version = "2.0")
  public static class ReadOnly extends MockDriver
      implements ReadableDriver, WrappingDriver {
    
    @Override
    public void save(Key key) {
      super.save(key); // just for accounting
      fail("Save should not be called on read-only drivers.");
    }
    
    @Override
    public boolean erase() {
      boolean value = super.erase(); // just for accounting
      fail("Erase should not be called on read-only drivers.");
      return value;
    }
  }

  /**
   * A write-only version of the mock driver. 
   */
  @DriverInfo(id = "mock-wo", name = "Write-Only Mock Driver", version = "3.0")
  public static class WriteOnly extends MockDriver
      implements WritableDriver, WrappingDriver {
    
    @Override
    public Key load() throws StoreException {
      Key key = super.load(); // just for accounting
      fail("Load should not be called on write-only drivers.");
      return key;
    }
    
    @Override
    public boolean isEmpty() {
      boolean value = super.isEmpty(); // just for accounting
      fail("IsEmpty should not be called on write-only drivers.");
      return value;
    }
  }

  /**
   * A no-wrap-support version of the mock driver.
   */
  @DriverInfo(id = "mock-nw", name = "No-Wrap Mock Driver", version = "4.0")
  public static class NoWrap extends MockDriver
      implements ReadableDriver, WritableDriver {
    
    @Override
    public void wrapWith(Key key) {
      super.wrapWith(key); // just for accounting
      fail("WrapWith should not be called on no-wrap drivers.");
    }
    
    @Override
    public boolean isWrapping() {
      boolean value = super.isWrapping(); // just for accounting
      fail("IsWrapping should not be called on no-wrap drivers.");
      return value;
    }
  }

  /**
   * A version of the mock driver that accepts all URI schemes.
   */
  @DriverInfo(id = "mock-aa", name = "Accept-All Mock Driver", version = "5.0")
  public static class AcceptAll extends MockDriver
      implements ReadableDriver, WritableDriver, WrappingDriver {
    
    @Override
    public URI open(URI address)
        throws IllegalAddressException, StoreException {
      try {
        return super.open(new URI(
            getInfo().id(),
            address.getSchemeSpecificPart(),
            address.getFragment()).normalize());
      } catch (URISyntaxException ex) {
        throw new IllegalAddressException(address, "Transform failure.", ex);
      }
    }
  }
  
  /**
   * A version of the mock driver that accepts only it's own scheme and the
   * "file" scheme.
   */
  @DriverInfo(id = "mock-af", name = "Accept-File Mock Driver", version = "6.0")
  public static class AcceptFile extends MockDriver 
      implements ReadableDriver, WritableDriver, WrappingDriver {
    
    @Override
    public URI open(URI address)
        throws IllegalAddressException, StoreException {
      String scheme = address.getScheme();
      try {
        if (getInfo().id().equalsIgnoreCase(scheme)
            || "file".equalsIgnoreCase(scheme)) {
          return super.open(new URI(
              getInfo().id(),
              address.getSchemeSpecificPart(),
              address.getFragment()).normalize());
        }
        throw new IllegalAddressException(
            address, IllegalAddressException.Reason.INVALID_SCHEME, null);
      } catch (URISyntaxException ex) {
        throw new IllegalAddressException(address, "Transform failure.", ex);
      }
    }
  }  
}
