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
import com.google.k2crypto.K2Exception;
import com.google.k2crypto.KeyVersionFactory;

import java.net.URI;

/**
 * Driver interface for a {@link Key} storage location.
 * 
 * Drivers are concrete implementations of a {@link Store}. In addition to
 * implementing this interface, the instantiatable driver class must be
 * annotated with {@link StoreDriverInfo} and provide a public constructor that
 * accepts a {@link java.net.URI URI} address and a {@link KeyVersionFactory}. Neither
 * of these arguments can be null. When instantiated, the driver must be in a
 * "closed" state; resources required for performing storage operations must not
 * be allocated until {@link #open()} is invoked. Drivers need not be concerned
 * with thread safety; the {@link Store} will ensure that all method calls will
 * be synchronized. 
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public interface StoreDriver {

  /**
   * Returns the storage location that the Key will be read from or written to,
   * as provided through the constructor. Must never return null or have any
   * other side effects.
   */
  URI getAddress();
  
  /**
   * Returns the factory that will be used to create Keys, as provided through
   * the constructor.  Must never return null or have any other side effects.
   */
  KeyVersionFactory getFactory();
  
  /**
   * Prepares the driver instance for performing storage operations by
   * allocating resources, establishing network connections, etc. The driver
   * may assume that this is only called once.
   * 
   * Possible failure scenarios:
   * An open may fail if the driver is file system-based and the provided path
   * in the URI points to an unsuitable location, e.g. it contains existing
   * files not recognizable by the driver or the path has illegal characters.
   * 
   * @throws K2Exception if there is a problem opening the driver
   */
  void open() throws K2Exception;
  
  /**
   * Closes the driver instance. Once this method returns, all resources
   * should be freed. The driver may assume that no other method will be
   * invoked after a close.
   */
  void close();
  
  /**
   * Returns true if there is no Key stored at this location,
   * false if one might be present.
   * 
   * Note that if this method returns false, there is no a guarantee that the
   * Key will actually be readable. The data might be encrypted, corrupted
   * or be in an invalid format. An attempt must be made to {@link #load()} to
   * know for sure if it is readable.
   * 
   * @throws K2Exception if the store could not be queried
   */
  boolean isEmpty() throws K2Exception;
    
  /**
   * Indicates that subsequent saves/loads on this instance should
   * be wrapped/unwrapped with the provided Key.
   * 
   * Generally, drivers do not need to check if the Key is acceptable for
   * wrapping keys, unless only specific key types are supported. High-level
   * purpose checking will be enforced by {@link Store}.
   * 
   * @param key Key protecting the actual stored key, or null to
   * disable wrapping
   * 
   * @throws K2Exception if the specified Key cannot be used for wrapping
   * @throws UnsupportedOperationException if a Key is provided and wrapping
   * is not supported
   */
  void wrapWith(Key key) throws K2Exception;
  
  /**
   * Saves the given Key to the store. Any existing Key will be
   * silently replaced, regardless of whether it is wrapped.
   *  
   * @param key Key to save
   * 
   * @throws K2Exception if there is some issue saving the given Key
   * @throws NullPointerException if key is null
   * @throws UnsupportedOperationException if this storage driver is read only
   */
  void save(Key key) throws K2Exception;
    
  /**
   * Loads the Key stored at this location. 
   * 
   * @return the stored key or null if the location is empty
   * 
   * @throws K2Exception if there is some issue loading the stored data
   */
  Key load() throws K2Exception;
 
  /**
   * Erases any stored Key, regardless of whether it is wrapped.
   * 
   * @return true if there was data present and it is has been erased, false
   * otherwise.
   * 
   * @throws K2Exception if there is some issue erasing stored data
   * @throws UnsupportedOperationException if this storage driver is read only
   */
  boolean erase() throws K2Exception;
    
}
