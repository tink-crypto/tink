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
import com.google.k2crypto.storage.driver.AddressUtilities;
import com.google.k2crypto.storage.driver.Driver;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * Main interface that the storage API exposes to the rest of K2.
 * 
 * <p>This class is thread-safe.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public class K2Storage {

  // Context for the current K2 session
  private final K2Context context;
  
  // Map of driver identifiers to installed drivers
  private final Map<String, InstalledDriver> drivers =
      new LinkedHashMap<String, InstalledDriver>();
  
  // Cache of the latest list of installed drivers
  private List<InstalledDriver> cachedDriverList = null;
  
  /**
   * Constructs a K2Storage interface for the given context.
   * 
   * @param context Context of the current K2 session.
   */
  public K2Storage(K2Context context) {
    this.context = context;
  }
  
  /**
   * Convenience method for loading a Key from a given address.
   * 
   * <p>This method is equivalent to calling {@link #open(String)}, followed
   * by a {@link Store#load()} and a {@link Store#close()} on the resulting
   * {@link Store}.
   * 
   * @param address String address of the key storage location.
   * 
   * @throws IllegalAddressException if the address is not a valid URI or if it
   *                                 is not recognized by the driver.
   * @throws NoSuitableDriverException if the address cannot be handled by any
   *                                   installed driver.
   * @throws StoreException if there was an issue reading from the location. 
   * 
   * @return Key read from the specified address.
   */
  public Key load(String address)
      throws IllegalAddressException,
             NoSuitableDriverException,
             StoreException {
    Store store = open(address);
    try {
      return store.load();
    } finally {
      store.close();
    }
  }
  
  /**
   * Convenience method for loading a Key from a given address.
   * 
   * <p>This method is equivalent to calling {@link #open(URI)}, followed
   * by a {@link Store#load()} and a {@link Store#close()} on the resulting
   * {@link Store}.
   * 
   * @param address URI address of the key storage location.
   * 
   * @throws IllegalAddressException if the address is not a valid URI or if it
   *                                 is not recognized by the driver.
   * @throws NoSuitableDriverException if the address cannot be handled by any
   *                                   installed driver.
   * @throws StoreException if there was an issue reading from the location. 
   * 
   * @return Key read from the specified address.
   */
  public Key load(URI address)
      throws IllegalAddressException,
             NoSuitableDriverException,
             StoreException {
    Store store = open(address);
    try {
      return store.load();
    } finally {
      store.close();
    }
  }

  /**
   * Convenience method for saving a Key to a given address.
   * 
   * <p>This method is equivalent to calling {@link #open(String)}, followed
   * by a {@link Store#save(Key)} and a {@link Store#close()} on the resulting
   * {@link Store}.
   * 
   * @param address String address of the key storage location.
   * @param key Key to save.
   * 
   * @throws IllegalAddressException if the address is not a valid URI or if it
   *                                 is not recognized by the driver.
   * @throws NoSuitableDriverException if the address cannot be handled by any
   *                                   installed driver.
   * @throws StoreException if there was an issue writing to the location. 
   */
  public void save(String address, Key key)
      throws IllegalAddressException,
             NoSuitableDriverException,
             StoreException {
    Store store = open(address);
    try {
      store.save(key);
    } finally {
      store.close();
    }    
  }

  /**
   * Convenience method for saving a Key to a given address.
   * 
   * <p>This method is equivalent to calling {@link #open(URI)}, followed
   * by a {@link Store#save(Key)} and a {@link Store#close()} on the resulting
   * {@link Store}.
   * 
   * @param address URI address of the key storage location.
   * @param key Key to save.
   * 
   * @throws IllegalAddressException if the address is not a valid URI or if it
   *                                 is not recognized by the driver.
   * @throws NoSuitableDriverException if the address cannot be handled by any
   *                                   installed driver.
   * @throws StoreException if there was an issue writing to the location. 
   */
  public void save(URI address, Key key)
      throws IllegalAddressException,
             NoSuitableDriverException,
             StoreException {
    Store store = open(address);
    try {
      store.save(key);
    } finally {
      store.close();
    }    
  }
  
  /**
   * Opens a storage location for reading/writing of a {@link Key}.
   * 
   * <p>The string address should be parsable as a URI. For convenience sake,
   * the common characters {@code ' '} (spaces) and {@code '%'} (percent
   * characters not followed by two hex digits) are automatically
   * percent-encoded. All other invalid URI characters must be manually escaped
   * by the caller, e.g. {@code "/{my_keys^2}"} should be
   * {@code "/%7Bmy_keys%5e2%7D"}.
   *  
   * <p>This method will search for an installed driver with an identifier
   * matching the scheme of the URI. If no such driver is found (or the scheme
   * is omitted), the available drivers will be queried in installation order
   * and the first driver that accepts the address will be used.
   * 
   * @param address Address string of the key storage location.
   * 
   * @return an open store pointing to the specified address.
   * 
   * @throws IllegalAddressException if the address is not a valid URI or if it
   *                                 is not recognized by the specified driver.
   * @throws NoSuitableDriverException if the address cannot be handled by any
   *                                   installed driver.
   * @throws StoreException if there was an issue opening the location. 
   */
  public Store open(String address)
      throws IllegalAddressException,
             NoSuitableDriverException,
             StoreException {
    if (address == null) {
      throw new NullPointerException("address");
    }
    address = AddressUtilities.encodeConvenience(address);

    try {
      return open(new URI(address));
    } catch (URISyntaxException ex) {
      throw new IllegalAddressException(
          address, IllegalAddressException.Reason.INVALID_URI, ex);
    }
  }
  
  /**
   * Opens a storage location for reading/writing of a {@link Key}.
   * 
   * <p>This method will search for an installed driver with an identifier
   * matching the scheme of the URI. If no such driver is found (or the scheme
   * is omitted), the available drivers will be queried in installation order
   * and the first driver that accepts the address will be used.
   * 
   * @param address URI address of the key storage location.
   * 
   * @return an open store pointing to the specified address.
   * 
   * @throws IllegalAddressException if the address is not recognized by the
   *                                 driver specified with the URI scheme.
   * @throws NoSuitableDriverException if the address cannot be handled by any
   *                                   installed driver.
   * @throws StoreException if there was an issue opening the location. 
   */
  public Store open(URI address)
      throws IllegalAddressException,
             NoSuitableDriverException,
             StoreException {    
    if (address == null) {
      throw new NullPointerException("address");
    }
    
    // We have to manually clean up any encoded unreserved characters because
    // Java's URI class does not do this for us. 
    address = AddressUtilities.decodeUnreserved(address);
    
    // Grab scheme to find a driver
    String scheme = address.getScheme();
    if (scheme != null) {
      scheme = scheme.toLowerCase(); // Case-insensitive matching
    }
    
    // We atomically query for a suitable driver,
    // or all the available drivers if we need to search.
    InstalledDriver driver;
    List<InstalledDriver> installedDrivers = null;
    synchronized (drivers) {
      driver = (scheme == null ? null : drivers.get(scheme));
      if (driver == null) {
        installedDrivers = getInstalledDrivers();
      }
    }
    
    // We have an exact scheme/driver match, open a Store on that driver.
    if (driver != null) {
      return new Store(driver, address).open();
    }
    
    // Otherwise, search for a compatible driver in installation order.
    for (InstalledDriver idriver : installedDrivers) {
      try {
        return new Store(idriver, address).open();
      } catch (IllegalAddressException ex) {
        // Ignored
      } catch (StoreException ex) {
        // Ignored
      }
    }
    
    // Could not find a driver
    throw new NoSuitableDriverException(address);
  }

  /**
   * Installs a storage driver.
   * 
   * @param driverClass Class of the driver implementation to install.
   *                    See {@link Driver} for specifications. 
   * 
   * @return {@link InstalledDriver} if successfully installed, {@code null}
   *         if a driver with the same identifier is already installed.
   *         
   * @throws StorageDriverException if there is a problem with the driver
   *                                implementation.
   */
  public InstalledDriver installDriver(Class<? extends Driver> driverClass) 
      throws StorageDriverException {
    
    InstalledDriver driver = new InstalledDriver(context, driverClass);
    String id = driver.getId();
    
    synchronized (drivers) {
      InstalledDriver existing = drivers.get(id);
      if (existing != null) {
        return null;
      }
      drivers.put(id, driver);
      cachedDriverList = null;
      return driver;
    }
  }
  
  /**
   * Uninstalls a driver.
   * 
   * @param id Identifier of the driver to uninstall.
   * 
   * @return {@code true} if successfully uninstalled, {@code false} if no
   *         such driver exists.
   */
  public boolean uninstallDriver(String id) {
    if (id == null) {
      throw new NullPointerException("id");
    }
    synchronized (drivers) {
      if (drivers.remove(id) != null) {
        cachedDriverList = null;
        return true;
      }
      return false;
    }
  }
  
  /**
   * Returns an immutable thread-safe list of the currently installed drivers,
   * in installation order.
   */
  public List<InstalledDriver> getInstalledDrivers() {
    synchronized (drivers) {
      List<InstalledDriver> list = cachedDriverList;
      if (list == null) {
        list = Collections.unmodifiableList(
            new ArrayList<InstalledDriver>(drivers.values()));
        cachedDriverList = list;
      }
      return list;      
    }
  }
}
