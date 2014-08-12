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
import com.google.k2crypto.Key;
import com.google.k2crypto.storage.driver.Driver;
import com.google.k2crypto.storage.driver.ReadableDriver;
import com.google.k2crypto.storage.driver.WrappingDriver;
import com.google.k2crypto.storage.driver.WritableDriver;

import java.net.URI;

/**
 * The interface to access a {@link Key} storage location.
 * 
 * <p>This class is conditionally thread-safe; {@link #wrapWith(Key)} and
 * {@link #noWrap()} should not be called concurrently to avoid
 * non-deterministic {@link #save(Key)} and {@link #load()} behavior.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public class Store {
  
  // Context for the current K2 session
  private final K2Context context;

  // Driver installation backing the store
  private final InstalledDriver installedDriver;
  
  // Driver instance being wrapped
  private final Driver driver;

  // Storage address that the store points to
  private URI address;

  // Synchronization lock
  private final Object lock = new int[0]; 

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
   * @param address Address to open the store with. 
   */
  Store(InstalledDriver installedDriver, URI address) {
    if (installedDriver == null) {
      throw new NullPointerException("installedDriver");
    } else if (address == null) {
      throw new NullPointerException("address");
    }
    this.installedDriver = installedDriver;
    this.context = installedDriver.getContext();
    this.driver = installedDriver.instantiate();
    
    // The address could also be passed in through open(), but the constructor
    // seems safer because hashCode(), equals() and toString() depend on address
    // not being null. We do not want the object to be in a completely broken
    // state after construction.
    this.address = address;
  }

  /**
   * Returns the context associated with the Store.
   */
  public K2Context getContext() {
    return context;
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
   * Provides access to the driver instance (for testing).
   */
  Driver getDriver() {
    return driver;
  }
  
  /**
   * Opens the store for loading/saving keys.
   * 
   * @return the opened store.
   * 
   * @throws IllegalAddressException if the address is not recognized. 
   * @throws StoreStateException if the store is already opened (or closed).
   * @throws StoreException if there is a driver-specific issue.
   */
  Store open() throws IllegalAddressException, StoreException {
    // This method is package-restricted because K2Storage automatically
    // opens the Store; there is no need for external code to see open().
    try {
      synchronized (lock) {
        switch (state) {
          default: // Closed
            throw new StoreStateException(
                StoreStateException.Reason.ALREADY_CLOSED);
          case OPEN:
            throw new StoreStateException(
                StoreStateException.Reason.ALREADY_OPEN);
          case INITIAL:
            // The driver may hurl on open(), so we defer changing state till
            // after it is done. Depending on the driver, it may not be safe
            // to invoke the read/write methods if open() fails.
            URI driverAddress = driver.open(address);
            if (driverAddress != null) {
              // Driver may provide a transformed address on open()
              address = driverAddress;
            }
            state = State.OPEN;
        }
      }
    } catch (StoreException ex) {
      ex.setStore(this);
      throw ex;
    }
    return this;
  }

  /**
   * Closes the store and frees any allocated resources. Reopening the store is
   * not permitted.
   */
  public void close() {
    synchronized (lock) {
      try {
        if (state == State.OPEN) {
          driver.close();
        }
      } finally {
        // No matter what happens, we want the state to be
        // closed when this is done.
        state = State.CLOSED;
      }
    }
  }
  
  /**
   * Returns {@code true} if, and only if, the store is open.
   */
  public boolean isOpen() {
    synchronized (lock) {
      return state == State.OPEN;
    }    
  }
  
  /**
   * Utility method to check if the store is open for business. 
   * 
   * @throws StoreStateException if the store is not open.
   */
  private void checkOpen() throws StoreStateException {
    synchronized (lock) {
      switch (state) {
        default: // Closed
          throw new StoreStateException(
              StoreStateException.Reason.ALREADY_CLOSED);
        case INITIAL:
          throw new StoreStateException(
              StoreStateException.Reason.NOT_OPEN);          
        case OPEN:
      }
    }
  }

  /**
   * Indicates that subsequent saves/loads on this store should be
   * wrapped/unwrapped with the provided key.
   * 
   * @param key Key protecting the actual stored key.
   * 
   * @return this Store, for method chaining.
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
    try {
      synchronized (lock) {
        checkOpen();
        if (driver instanceof WrappingDriver) {
          ((WrappingDriver)driver).wrapWith(key);
        } else {
          throw new UnsupportedByStoreException(
              UnsupportedByStoreException.Reason.NO_WRAP);
        }
      }
    } catch (StoreException ex) {
      ex.setStore(this);
      throw ex;
    }
    return this;
  }
  
  /**
   * Indicates that subsequent saves/loads on this store will not be wrapped.
   * 
   * @return this Store, for method chaining.
   *
   * @throws StoreStateException if the store is not open.
   * @throws StoreException if there is a driver-specific issue with disabling
   *                        wrapping.
   */
  public Store noWrap() throws StoreException {
    try {
      synchronized (lock) {
        checkOpen();
        // We are basically expanding wrapWith implemented at the driver
        // so that it will be clearer to the user of the store
        if (driver instanceof WrappingDriver) {
          ((WrappingDriver)driver).wrapWith(null);
        }
      }
    } catch (StoreException ex) {
      ex.setStore(this);
      throw ex;
    }
    return this;    
  }
  
  /**
   * Returns {@code true} if a wrapping key is currently set (with
   * {@link #wrapWith(Key)}), {@code false} otherwise.
   * 
   * @throws StoreStateException if the store is not open.
   * @throws StoreException if there is a driver-specific issue.
   */
  public boolean isWrapping() throws StoreException {
    try {
      synchronized (lock) {
        checkOpen();
        if (driver instanceof WrappingDriver) {
          return ((WrappingDriver)driver).isWrapping();
        }
      }
    } catch (StoreException ex) {
      ex.setStore(this);
      throw ex;
    }
    return false;
  }
  
  /**
   * Returns {@code true} if there is no key stored at this location,
   * {@code false} if one might be present.
   * 
   * <p>Note that if this method returns false, there is no a guarantee that
   * the key will actually be readable. The data might be encrypted, corrupted
   * or be in an invalid format. An attempt must be made to {@link #load()} to
   * know for sure if it is readable.
   * 
   * @throws StoreStateException if the store is not open.
   * @throws StoreIOException if there is an I/O issue with checking emptiness.
   * @throws UnsupportedByStoreException if the store is write-only.
   * @throws StoreException if there is a driver-specific issue.
   */
  public boolean isEmpty() throws StoreException {
    try {
      synchronized (lock) {
        checkOpen();
        if (driver instanceof ReadableDriver) {
          return ((ReadableDriver)driver).isEmpty();
        } else {
          // Non-readable implies the driver must be writable
          throw new UnsupportedByStoreException(
              UnsupportedByStoreException.Reason.WRITE_ONLY);
        }
      }
    } catch (StoreException ex) {
      ex.setStore(this);
      throw ex;
    }
  }
  
  /**
   * Saves the given key to the store. Any existing key will be silently
   * replaced, regardless of whether it is wrapped.
   *  
   * @param key Key to save.
   * 
   * @throws StoreStateException if the store is not open.
   * @throws StoreIOException if there is an I/O issue with saving the key.
   * @throws UnsupportedByStoreException if the store is read-only.
   * @throws StoreException if there is a driver-specific issue with saving.
   */
  public void save(Key key) throws StoreException {
    if (key == null) {
      throw new NullPointerException("key");
    }
    try {
      synchronized (lock) {
        checkOpen();
        if (driver instanceof WritableDriver) {
          ((WritableDriver)driver).save(key);
        } else {
          // Non-writable implies the driver must be readable
          throw new UnsupportedByStoreException(
              UnsupportedByStoreException.Reason.READ_ONLY);
        }
      }
    } catch (StoreException ex) {
      ex.setStore(this);
      throw ex;
    }
  }
  
  /**
   * Loads the key stored at this location. 
   * 
   * @return the stored key or null if the location is empty.
   * 
   * @throws StoreStateException if the store is not open.
   * @throws StoreIOException if there is an I/O issue with loading the key.
   * @throws UnsupportedByStoreException if the store is write-only.
   * @throws StoreException if there is a driver-specific issue with loading.
   */
  public Key load() throws StoreException {
    try {
      synchronized (lock) {
        checkOpen();
        if (driver instanceof ReadableDriver) {
          return ((ReadableDriver)driver).load();
        } else {
          // Non-readable implies the driver must be writable
          throw new UnsupportedByStoreException(
              UnsupportedByStoreException.Reason.WRITE_ONLY);
        }
      }
    } catch (StoreException ex) {
      ex.setStore(this);
      throw ex;
    }
  }
  
  /**
   * Erases any stored key, regardless of whether it is wrapped.
   * 
   * @return {@code true} if, and only if, there was data present and it has
   *         been erased.
   * 
   * @throws StoreStateException if the store is not open.
   * @throws StoreIOException if there is an I/O issue with erasing the key.
   * @throws UnsupportedByStoreException if the store is read-only.
   * @throws StoreException if there is a driver-specific issue with erasing.
   */
  public boolean erase() throws StoreException {
    try {
      synchronized (lock) {
        checkOpen();
        if (driver instanceof WritableDriver) {
          return ((WritableDriver)driver).erase();
        } else {
          // Non-writable implies the driver must be readable
          throw new UnsupportedByStoreException(
              UnsupportedByStoreException.Reason.READ_ONLY);
        }
      }
    } catch (StoreException ex) {
      ex.setStore(this);
      throw ex;
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
      return other.address.equals(address)
          && other.installedDriver.equals(installedDriver);
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
