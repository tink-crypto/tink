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

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Mock implementation of a store driver. The mock, by default, is most 
 * permissively declared (i.e. not read-only and supports key wrapping).
 * However, it will reject addresses that have a schemes that do not match
 * its identifier.
 * <p>
 * The mock will raise assertion errors if it is used in a manner
 * that violates expected {@link Store} behavior.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
@StoreDriverInfo(id="mock", name="Mock Store", version="1.0",
    readOnly=false, wrapSupported=true)
public class MockStoreDriver implements StoreDriver {
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
  StoreDriverInfo getInfo() {
    StoreDriverInfo info = getClass().getAnnotation(StoreDriverInfo.class);
    if (info == null) {
      fail("There should be an annotation.");
    }
    return info;
  }
  
  /**
   * @see StoreDriver#initialize(K2Context)
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
   * @see StoreDriver#open(java.net.URI)
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
      throw new IllegalAddressException(address,
          IllegalAddressException.Reason.INVALID_SCHEME, null);
    }
    
    this.address = address;
    return address;
  }

  /**
   * @see StoreDriver#close()
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
   * @see StoreDriver#wrapWith(Key)
   */
  public void wrapWith(Key key) throws StoreException {
    ++wrapWithCalls;
    checkOpen();
    wrapKey = key;
  }

  /**
   * @see StoreDriver#isWrapping()
   */
  public boolean isWrapping() {
    ++isWrappingCalls;
    checkOpen();
    return wrapKey != null;
  }

  /**
   * @see StoreDriver#isEmpty()
   */
  public boolean isEmpty() throws StoreException {
    ++isEmptyCalls;
    checkOpen();
    return storedKey == null;
  }

  /**
   * @see StoreDriver#save(Key)
   */
  public void save(Key key) throws StoreException {
    ++saveCalls;
    if (key == null) {
      fail("Key to save should never be null.");
    }
    checkOpen();
    storedKey = key;
    storedKeyWrapper = wrapKey;
  }

  /**
   * @see StoreDriver#load()
   */
  public Key load() throws StoreException {
    ++loadCalls;
    checkOpen();
    if (storedKey != null) {
      if (storedKeyWrapper == null) {
        if (wrapKey != null) {
          throw new WrapKeyException(WrapKeyException.Reason.UNNECESSARY);                  
        }
      } else if (!storedKeyWrapper.equals(wrapKey)) {
        throw new WrapKeyException(wrapKey == null ?
            WrapKeyException.Reason.REQUIRED : WrapKeyException.Reason.WRONG);        
      }
      return storedKey;
    }
    return null;
  }

  /**
   * @see StoreDriver#erase()
   */
  public boolean erase() throws StoreException {
    ++eraseCalls;
    checkOpen();
    Key erasedKey = storedKey;
    storedKey = null;
    storedKeyWrapper = null;
    return erasedKey != null;
  }
  
  /**
   * A read-only version of the mock driver. 
   */
  @StoreDriverInfo(id="mock-ro", name="Read-Only Mock Store", version="2.0",
      readOnly=true, wrapSupported=true)
  public static class ReadOnly extends MockStoreDriver {
    
    @Override
    public void save(Key key) throws StoreException {
      super.save(key); // just for accounting
      fail("Save should not be called on read-only drivers.");
    }
    
    @Override
    public boolean erase() throws StoreException {
      boolean value = super.erase(); // just for accounting
      fail("Erase should not be called on read-only drivers.");
      return value;
    }
  }

  /**
   * A no-wrap-support version of the mock driver.
   */
  @StoreDriverInfo(id="mock-nw", name="No-Wrap Mock Store", version="3.0",
      readOnly=false, wrapSupported=false)
  public static class NoWrap extends MockStoreDriver {
    
    @Override
    public void wrapWith(Key key) throws StoreException {
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
  @StoreDriverInfo(id="mock-aa", name="Accept-All Mock Store",
      version="4.0", readOnly=false, wrapSupported=true)
  public static class AcceptAll extends MockStoreDriver {
    
    @Override
    public URI open(URI address)
        throws IllegalAddressException, StoreException {
      try {
        return super.open(new URI(getInfo().id(),
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
  @StoreDriverInfo(id="mock-af", name="Accept-File Mock Store",
      version="5.0", readOnly=false, wrapSupported=true)
  public static class AcceptFile extends MockStoreDriver {
    
    @Override
    public URI open(URI address)
        throws IllegalAddressException, StoreException {
      String scheme = address.getScheme();
      try {
        if (getInfo().id().equalsIgnoreCase(scheme) ||
            "file".equalsIgnoreCase(scheme)) {
          return super.open(new URI(getInfo().id(),
              address.getSchemeSpecificPart(),
              address.getFragment()).normalize());
        }
        throw new IllegalAddressException(address,
            IllegalAddressException.Reason.INVALID_SCHEME, null);
      } catch (URISyntaxException ex) {
        throw new IllegalAddressException(address, "Transform failure.", ex);
      }
    }
  }  
}
