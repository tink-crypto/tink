// Copyright 2014 Google. Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.k2crypto.storage;

import com.google.k2crypto.Key;
import com.google.k2crypto.KeyVersionFactory;

import java.net.URI;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * The interface to access a {@link Key} storage location.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public class Store {

  // Driver being wrapped (from constructor)
  private final StoreDriver driver;

  // Storage address is obtained from driver
  private final URI address;

  // Driver info is obtained from driver
  private final StoreDriverInfo driverInfo;

  // Synchronization lock (from constructor)
  private final Lock lock; 

  // Initial state is always the initial state
  private State state = State.INITIAL;
  
  // Possible states of the store object
  private enum State {
    INITIAL, OPEN, CLOSED
  }
  
  /**
   * Constructs a Store that wraps the given driver. 
   * 
   * @param driver Driver to wrap.
   * 
   * @throws BadDriverException if there is something wrong with the driver.
   */
  Store(StoreDriver driver) throws BadDriverException {
    this(driver, new ReentrantLock());
  }
  
  /**
   * Constructs a Store that wraps the given driver and uses the provided lock
   * for synchronization.
   * 
   * @param driver Driver to wrap.
   * @param lock Lock instance to use.
   * 
   * @throws BadDriverException if there is something wrong with the driver.
   */
  Store(StoreDriver driver, Lock lock) throws BadDriverException {
    if (driver == null) {
      throw new NullPointerException("Driver should not be null.");
    }
    else if (lock == null) {
      throw new NullPointerException("Lock should not be null.");
    }
    
    address = driver.getAddress();
    if (address == null) {
      throw new BadDriverException(driver.getClass(),
          "Address on driver should not be null.");
    }

    driverInfo = driver.getClass().getAnnotation(StoreDriverInfo.class);
    if (driverInfo == null) {
      throw new BadDriverException(driver.getClass(),
          "Driver is missing meta-data annotation.");
    }
    
    this.driver = driver;
    this.lock = lock;
  }
  
  /**
   * Returns the hash-code for the store, which is the hash of the URI address.
   */
  @Override
  public int hashCode() {
    return address.hashCode();
  }
  
  /**
   * Tests the store for equality with an object.
   * 
   * @param obj Object to compare to.
   * 
   * @return {@code true} if, and only if, the object is also a Store and it
   *         has the same address as this one. 
   */
  @Override
  public boolean equals(Object obj) {
    return obj instanceof Store && ((Store)obj).address.equals(address);
  }
  
  @Override
  public String toString() {
    return address + "(" + state + ")";
  }
  
  /**
   * Returns the address of the storage location that keys will be read from
   * or written to.
   */
  public URI getAddress() {
    return address;
  }
  
  /**
   * Returns the factory that will be used to create KeyVersions.
   */
  public KeyVersionFactory getFactory() {
    return driver.getFactory();
  }
  
  /**
   * Opens the store for loading/saving keys. Has no effect if the store is
   * already open.
   * 
   * @throws StoreStateException if the store has already been closed.
   * @throws StoreException if there is a driver-specific issue.
   */
  public void open() throws StoreException {
    lock.lock();
    try {
      switch (state) {
        default: // Closed
          throw new StoreStateException(this, "Store already closed.");
        case INITIAL:
          // The driver may hurl on open(), so we defer changing state till
          // after it is done. Depending on the driver, it may not be safe
          // to invoke the read/write methods if open() fails.
          driver.open();
          state = State.OPEN;
          break;
        case OPEN:
      }
    }
    finally {
      lock.unlock();
    }
  }

  /**
   * Closes the store and frees any allocated resources. Reopening the store is
   * not permitted.
   */
  public void close() {
    lock.lock();
    try {
      if (state == State.OPEN) {
        driver.close();
      }
    }
    finally {
      // No matter what happens, we want the state to be closed when this
      // is done. Should not affect the unlock...
      state = State.CLOSED;
      lock.unlock();
    }
  }
  
  /**
   * Returns {@code true} if, and only if, the store is open.
   */
  public boolean isOpen() {
    lock.lock();
    try {
      return state == State.OPEN;
    }
    finally {
      lock.unlock();
    }    
  }
  
  /**
   * Utility method to check if the store is open for business. 
   * 
   * @throws StoreStateException if the store is not open.
   */
  private void checkOpen() throws StoreStateException {
    if (state != State.OPEN) {
      throw new StoreStateException(this, "Store not open.");
    }    
  }
  
  /**
   * Returns {@code true} if there is no key stored at this location,
   * {@code false} if one might be present.
   * <p>
   * Note that if this method returns false, there is no a guarantee that the
   * key will actually be readable. The data might be encrypted, corrupted
   * or be in an invalid format. An attempt must be made to {@link #load()} to
   * know for sure if it is readable.
   * 
   * @throws StoreStateException if the store is not open.
   * @throws StoreException if there is a driver-specific issue.
   */
  public boolean isEmpty() throws StoreException {
    lock.lock();
    try {
      checkOpen();
      return driver.isEmpty();
    }
    finally {
      lock.unlock();
    }
  }
  
  /**
   * Indicates that subsequent saves/loads on this store should be
   * wrapped/unwrapped with the provided key.
   * 
   * @param key Key protecting the actual stored key.
   * 
   * @throws StoreStateException if the store is not open.
   * @throws UnsupportedByStoreException if wrapping is not supported.
   * @throws StoreException if there is a driver-specific issue with the key.
   */
  public Store wrapWith(Key key) throws StoreException {
    // NOTE: the key might be unsuitable for wrapping because of purpose
    // restrictions, which means we will need to add a PurposeException later.
    if (key == null) {
      throw new NullPointerException("Wrap key cannot be null");
    }
    
    lock.lock();
    try {
      checkOpen();
      if (!driverInfo.wrapSupported()) {
        throw new UnsupportedByStoreException(this,
            "Store does not support wrapping of keys.");
      }
      driver.wrapWith(key);
    }
    finally {
      lock.unlock();
    }
    return this;
  }
  
  /**
   * Indicates that subsequent saves/loads on this store will not be wrapped.
   * 
   * @throws StoreStateException if the store is not open.
   * @throws StoreException if there is a driver-specific issue with disabling
   *                        wrapping.
   */
  public Store noWrap() throws StoreException {
    lock.lock();
    try {
      checkOpen();
      // We are basically expanding wrapWith implemented at the driver
      // so that it will be clearer to the user of the store
      if (driverInfo.wrapSupported()) {
        driver.wrapWith(null);
      }
    }
    finally {
      lock.unlock();
    }
    return this;    
  }
  
  /**
   * Saves the given key to the store. Any existing key will be silently
   * replaced, regardless of whether it is wrapped.
   *  
   * @param key Key to save.
   * 
   * @throws StoreStateException if the store is not open.
   * @throws StoreException if there is a driver-specific issue with saving.
   */
  public void save(Key key) throws StoreException {
    lock.lock();
    try {
      checkOpen();
      driver.save(key);
    }
    finally {
      lock.unlock();
    }
  }
  
  /**
   * Loads the key stored at this location. 
   * 
   * @return the stored key or null if the location is empty.
   * 
   * @throws StoreStateException if the store is not open.
   * @throws StoreException if there is a driver-specific issue with loading.
   */
  public Key load() throws StoreException {
    lock.lock();
    try {
      checkOpen();
      return driver.load();
    }
    finally {
      lock.unlock();
    }
  }
  
  /**
   * Erases any stored key, regardless of whether it is wrapped.
   * 
   * @return {@code true} if, and only if, there was data present and it has
   *         been erased.
   * 
   * @throws StoreStateException if the store is not open.
   * @throws StoreException if there is a driver-specific issue with erasing.
   */
  public boolean erase() throws StoreException {
    lock.lock();
    try {
      checkOpen();
      return driver.erase();
    }
    finally {
      lock.unlock();
    }
  }
  
}

