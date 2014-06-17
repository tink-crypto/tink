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

/**
 * Driver interface for a {@link Key} storage location.
 * <p>
 * Drivers are concrete implementations of a {@link Store}. In addition to
 * implementing this interface, the instantiatable driver class must be
 * annotated with {@link StoreDriverInfo} and provide a public constructor that
 * accepts a {@link java.net.URI URI} address and a {@link KeyVersionFactory}.
 * Neither of these arguments can be null. When instantiated, the driver must be
 * in a "closed" state; resources required for performing storage operations
 * must not be allocated until {@link #open()} is invoked. 
 * <p>
 * Drivers need not be concerned with thread safety, or methods invoked when
 * they are not supported, or methods invoked when {@code open()} has not neen
 * called, or methods invoked when {@code close()} has been called. The
 * {@link Store} wrapper will manage all access to the driver by ensuring that
 * calls are synchronized, methods are not invoked when inappropriate, etc. 
 * <p>
 * A note about open/close and network-based stores: It is possible for the
 * network connection to drop after the driver is opened. However, the driver
 * must not implicitly close the store in this event. As long as the store is
 * still open, the connection should be reattempted.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public interface StoreDriver {

  /**
   * Returns the address of the storage location that keys will be read from
   * or written to, as provided through the constructor. Must never return null
   * or have any other side effects.
   */
  URI getAddress();
  
  /**
   * Returns the factory that will be used to create KeyVersions, as provided
   * through the constructor. Must never return null or have any other side
   * effects.
   */
  KeyVersionFactory getFactory();
  
  /**
   * Prepares the driver instance for performing storage operations by
   * allocating resources, establishing network connections, etc. The driver
   * may assume that this is only called once.
   * <p>
   * An open may fail if the driver is file system-based and the provided path
   * in the URI points to an unsuitable location, e.g. it contains existing
   * files not recognizable by the driver or the path has illegal characters.
   * 
   * @throws StoreException if there is a problem opening the driver.
   */
  void open() throws StoreException;
  
  /**
   * Closes the driver instance. Once this method returns, all resources
   * should be freed. The driver may assume that no other method will be
   * invoked after a close.
   */
  void close();
  
  /**
   * Returns {@code true} if there is no key stored at this location,
   * {@code false} if one might be present.
   * <p>
   * Note that if this method returns false, there is no a guarantee that the
   * key will actually be readable. The data might be encrypted, corrupted
   * or be in an invalid format. An attempt must be made to {@link #load()} to
   * know for sure if it is readable.
   * 
   * @throws StoreException if the store could not be queried.
   */
  boolean isEmpty() throws StoreException;
    
  /**
   * Indicates that subsequent saves/loads on this store should be
   * wrapped/unwrapped with the provided key.
   * 
   * @param key Key protecting the actual stored key, or null to disable
   *            wrapping.
   * 
   * @throws StoreException if a key is provided and it cannot be used for
   *                        wrapping
   */
  void wrapWith(Key key) throws StoreException;
  
  /**
   * Saves the given key to the store. Any existing key will be silently
   * replaced, regardless of whether it is wrapped.
   *  
   * @param key Key to save.
   * 
   * @throws StoreException if there is some issue saving the given key.
   */
  void save(Key key) throws StoreException;
    
  /**
   * Loads the key stored at this location. 
   * 
   * @return the stored key or null if the location is empty.
   * 
   * @throws StoreException if there is some issue loading the stored data.
   */
  Key load() throws StoreException;
 
  /**
   * Erases any stored key, regardless of whether it is wrapped.
   * 
   * @return {@code true} if, and only if, there was data present and it has
   *         been erased.
   * 
   * @throws StoreException if there is some issue erasing stored data.
   */
  boolean erase() throws StoreException;
    
}
