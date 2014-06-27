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

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * Main interface that the storage API exposes to the rest of K2.
 * <p>
 * This class is thread-safe.
 * 
 * @author darylseah@google.com (Daryl Seah)
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
   * <p>
   * This method is equivalent to calling {@code open(address)}, followed by a
   * {@code load()} and a {@code close()} on the resulting {@link Store}.  
   * 
   * @param address Address of the key storage location.
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
   * Convenience method for saving a Key to a given address.
   * <p>
   * This method is equivalent to calling {@code open(address)}, followed by a
   * {@code save(key)} and a {@code close()} on the resulting {@link Store}.  
   * 
   * @param address Address of the key storage location.
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
   * Opens a storage location for reading/writing of a {@link Key}.
   * <p>
   * The string address should either be an absolute URI (i.e. complete with
   * a scheme identifying the driver to use) or a path. Reserved characters
   * should be URI-escaped if necessary, e.g. {@code "/My Keys"} should be
   * {@code "/My%20Keys"}. 
   * <p>
   * If the string is only a path (and nothing else), the path will be converted
   * to an absolute one (if necessary) and the scheme "file://" will be prefixed
   * to it.
   * <p>
   * This method will search for an installed driver with an identifier matching
   * the scheme of the URI. If no such driver is found, the available drivers
   * will be queried in installation order and the first driver that accepts
   * the address will be used.
   * 
   * @param address Address string of the key storage location.
   * 
   * @return an open store pointing to the specified address.
   * 
   * @throws IllegalAddressException if the address is not a valid URI or if it
   *                                 is not recognized by the driver.
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
    return open(stringToURI(address));
  }
  
  /**
   * Opens a storage location for reading/writing of a {@link Key}.
   * <p>
   * This method will search for an installed driver with an identifier matching
   * the scheme of the URI. If no such driver is found, the available drivers
   * will be queried in installation order and the first driver that accepts
   * the address will be used.
   * 
   * @param address URI address of the key storage location.
   * 
   * @return an open store pointing to the specified address.
   * 
   * @throws IllegalAddressException if the address is not a complete URI or if
   *                                 it is not recognized by the driver.
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
    
    // The URI must have a scheme
    String scheme = address.getScheme();
    if (scheme == null) {
      throw new IllegalAddressException(address,
          IllegalAddressException.Reason.NO_SCHEME, null);
    }
    scheme = scheme.toLowerCase();
    
    // We atomically query for a suitable driver,
    // or all the available drivers if we need to search.
    InstalledDriver driver;
    List<InstalledDriver> installedDrivers = null;
    synchronized (drivers) {
      driver = drivers.get(scheme);
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
   *                    See {@link StoreDriver} for specifications. 
   * 
   * @return {@code true} if successfully installed, {@code false} if a driver
   *         with the same identifier is already installed.
   *         
   * @throws StoreDriverException if there is a problem with the driver
   *                              implementation.
   */
  public boolean installDriver(Class<? extends StoreDriver> driverClass) 
      throws StoreDriverException {
    
    InstalledDriver driver = new InstalledDriver(context, driverClass);
    String id = driver.getId();
    
    synchronized (drivers) {
      InstalledDriver existing = drivers.get(id);
      if (existing != null) {
        return false;
      }
      drivers.put(id, driver);
      cachedDriverList = null;
      return true;
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
    synchronized (drivers) {
      if (drivers.remove(id) != null) {
        cachedDriverList = null;
        return true;
      }
      return false;
    }
  }
  
  /**
   * Returns an immutable thread-safe list of the currently installed drivers.
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
  
  /**
   * Converts a string address to a URI address. Escaped characters will be
   * interpreted.
   * <p>
   * If the string is only a path (and nothing else), this method will convert
   * the path to an absolute one (if necessary) and append "file://" to it.
   * 
   * @param address String address to convert.
   * @return the URI form of the string. 
   * @throws IllegalAddressException if the string could not be interpreted
   *                                 as a URI.
   */
  static URI stringToURI(String address) throws IllegalAddressException {
    URI uri;
    try {
      // Parse to a URI, then make sure a scheme is present
      uri = new URI(address).normalize();
      
      if (uri.getScheme() == null) {
        // If there is no scheme, we automatically append "file://" and resolve
        // relative paths ONLY if every other URI component is missing.
        if (uri.getUserInfo() == null &&
            uri.getHost() == null &&
            uri.getPort() < 0 &&
            uri.getQuery() == null &&
            uri.getFragment() == null) {
          
          // getPath() is used instead of getRawPath() so that any escaped
          // characters the user provides will be decoded. Otherwise, "%20"
          // will be interpreted as "%2520", i.e. a literal percent followed
          // by "20" instead of the space character.
          String path = uri.getPath();
          if (path == null || path.length() == 0) {
            // We cannot do automatic conversion without any path...
            throw new IllegalAddressException(address,
                IllegalAddressException.Reason.NO_PATH, null);
          }
          
          // Convert relative paths to absolute
          if (path.charAt(0) != '/') {
            path = new File("").toURI().getPath() + '/' + path;
          }
          
          // Reconstruct the URI
          uri = new URI("file", null, null, -1, path, null, null).normalize();
        }
        else {
          throw new IllegalAddressException(address,
              IllegalAddressException.Reason.NO_SCHEME, null);
        }
      }
    } catch (URISyntaxException ex) {
      throw new IllegalAddressException(address,
          IllegalAddressException.Reason.INVALID_URI, ex);
    }
    return uri;
  }
}
