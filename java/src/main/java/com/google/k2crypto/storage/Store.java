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

import com.google.k2crypto.K2Context;
import com.google.k2crypto.Key;

import java.net.URI;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * The interface to access a {@link Key} storage location.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public class Store {
  
  // Context for the current K2 session
  private final K2Context context;

  // Driver installation backing the store
  private final InstalledDriver installedDriver;
  
  // Driver instance being wrapped
  private final StoreDriver driver;

  // Storage address, as obtained from driver
  private final URI address;

  // Synchronization lock
  private final Lock lock; 

  // Initial state is always the initial state
  private State state = State.INITIAL;
  
  // Possible states of the store object
  private enum State {
    INITIAL, OPEN, CLOSED
  }
  
  /**
   * Constructs a Store that is backed by the given driver. 
   * 
   * @param installedDriver Driver installed for the store.
   * @param address Address to open the driver with.
   * 
   * @throws IllegalAddressException if the address cannot be interpreted by
   *                                 the driver.
   */
  Store(InstalledDriver installedDriver, URI address)
      throws IllegalAddressException {
    this(installedDriver, address, new ReentrantLock());
  }
  
  /**
   * Constructs a Store that is backed by given driver and uses the provided
   * lock for synchronization.
   * 
   * @param installedDriver Driver installed for the store.
   * @param address Address to open the driver with.
   * @param lock Lock instance to use.
   * 
   * @throws IllegalAddressException if the address cannot be interpreted by
   *                                 the driver.
   */
  Store(InstalledDriver installedDriver, URI address, Lock lock)
      throws IllegalAddressException {
    
    if (installedDriver == null) {
      throw new NullPointerException("installedDriver");
    } else if (address == null) {
      throw new NullPointerException("address");
    } else if (lock == null) {
      throw new NullPointerException("lock");
    }
    
    this.installedDriver = installedDriver;
    this.context = installedDriver.getContext();
    this.driver = installedDriver.instantiate(address);    
    URI driverAddress = driver.getAddress();
    this.address = (driverAddress == null ? address : driverAddress);
    this.lock = lock;
  }
  
  /**
   * Returns the address of the storage location that keys will be read from
   * or written to.
   */
  public URI getAddress() {
    return address;
  }
  
  /**
   * Returns information about the driver installation backing the store.
   */
  public InstalledDriver getInstalledDriver() {
    return installedDriver;
  }
  
  /**
   * Opens the store for loading/saving keys. Has no effect if the store is
   * already open.
   *
   * @return the opened store.
   * 
   * @throws StoreStateException if the store has already been closed.
   * @throws StoreException if there is a driver-specific issue.
   */
  Store open() throws StoreException {
    // This method is package-restricted because K2Storage automatically
    // opens the Store; there is no need for external code to see open().
    lock.lock();
    try {
      switch (state) {
        default: // Closed
          throw new StoreStateException(
              context.getStrings().get("storage.store.closed"));
        case INITIAL:
          // The driver may hurl on open(), so we defer changing state till
          // after it is done. Depending on the driver, it may not be safe
          // to invoke the read/write methods if open() fails.
          driver.open();
          state = State.OPEN;
          break;
        case OPEN:
      }
    } catch (StoreException ex) {
      ex.setStore(this);
      throw ex;
    } finally {
      lock.unlock();
    }
    return this;
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
    } finally {
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
    } finally {
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
      throw new StoreStateException(
          context.getStrings().get("storage.store.not_open"));
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
    } catch (StoreException ex) {
      ex.setStore(this);
      throw ex;
    } finally {
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
      throw new NullPointerException("key");
    }
    
    lock.lock();
    try {
      checkOpen();
      if (!installedDriver.isWrapSupported()) {
        throw new UnsupportedByStoreException(
            context.getStrings().get("storage.store.no_wrap"));
      }
      driver.wrapWith(key);
    } catch (StoreException ex) {
      ex.setStore(this);
      throw ex;
    } finally {
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
      if (installedDriver.isWrapSupported()) {
        driver.wrapWith(null);
      }
    } catch (StoreException ex) {
      ex.setStore(this);
      throw ex;
    } finally {
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
    } catch (StoreException ex) {
      ex.setStore(this);
      throw ex;
    } finally {
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
    } catch (StoreException ex) {
      ex.setStore(this);
      throw ex;
    } finally {
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
    } catch (StoreException ex) {
      ex.setStore(this);
      throw ex;
    } finally {
      lock.unlock();
    }
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
   *         has the same address and driver as this one. 
   */
  @Override
  public boolean equals(Object obj) {
    if (obj instanceof Store) {
      Store other = (Store)obj;
      return other.address.equals(address) &&
          other.installedDriver.equals(installedDriver);
    }
    return false;
  }
  
  /**
   * @see Object#toString()
   */
  @Override
  public String toString() {
    return address + "(" + state + ")";
  } 
}
