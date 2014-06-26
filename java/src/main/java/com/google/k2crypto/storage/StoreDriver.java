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

import java.net.URI;

/**
 * Driver interface for a {@link Key} storage location.
 * <p>
 * Drivers are concrete implementations of a {@link Store}. In addition to
 * implementing this interface, the instantiatable driver class must be
 * annotated with {@link StoreDriverInfo} and provide a public constructor
 * with no arguments. When instantiated, {@link #initialize(K2Context)}
 * will be invoked on the driver to provide the context of the current K2
 * session. After a successful initialization, {@link #open(URI)} will be
 * called to actually allocate resources for performing storage operations
 * on the specified storage address. This method may throw {@link
 * IllegalAddressException} if the address is not recognized by the
 * driver. Finally, {@link #close()} will be called to free resources, after
 * the user has performed the storage operations. Note that it is NOT safe to
 * allocate resources before {@link #open(URI)} is called, e.g. during
 * construction or on initialize.
 * <p>
 * Drivers need not be concerned with thread safety, or methods invoked when
 * they are not supported, or methods invoked when {@link #open(URI)} has not
 * been called, or methods invoked when {@link #close()} has been called. The
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
   * Initializes the driver instance with the K2 environment.
   * 
   * @param context Context of the K2 session.
   */
  void initialize(K2Context context);
  
  /**
   * Prepares the driver instance for performing storage operations by
   * allocating resources, establishing network connections, etc. The driver
   * may assume that this is only called once and only after
   * {@link #initialize(K2Context)} has been called.
   * <p>
   * An open may fail if the address is illegal with respect to the driver
   * implementation; e.g. it contains invalid characters that will not map
   * to any file-system. An open may also fail if the provided address is legal
   * but points to an unsuitable location; e.g. it contains existing files not
   * recognizable by the driver or points to a location that is not
   * readable/writable. Note that in the first case, resources need not be
   * allocated, while in the second case, files might need to be opened to
   * verify that the location is valid. Either way, if an open fails, the
   * driver must ensure that any partially allocated resources are freed;
   * {@link #close()} will not be called if {@code open()} throws an exception.
   * <p>
   * This method may also return a modified address to present to the user,
   * e.g. an address that has been normalized with driver-specific logic.
   * 
   * @param address Address of the storage location to open.
   * 
   * @return a transformed/normalized URI address, or {@code null} if there
   *         are no changes. 
   * 
   * @throws IllegalAddressException if the address is not recognized. 
   * @throws StoreException if there is a problem allocating resources or
   *                        accessing the given (valid) address.
   */
  URI open(URI address) throws IllegalAddressException, StoreException;
  
  /**
   * Closes the driver instance. Once this method returns, all resources
   * should be freed. The driver may assume that no other method will be
   * invoked after a close.
   */
  void close();
  
  /**
   * Indicates that subsequent saves/loads on this store should be
   * wrapped/unwrapped with the provided key.
   * <p>
   * The driver should, in its initial state, have no wrapping key set.
   * <p>
   * This method will only be called if the driver declares
   * {@code wrapSupport=true} with {@link StoreDriverInfo}.
   * 
   * @param key Key protecting the actual stored key, or null to disable
   *            wrapping.
   * 
   * @throws StoreException if a key is provided and it cannot be used for
   *                        wrapping
   */
  void wrapWith(Key key) throws StoreException;
  
  /**
   * Returns {@code true} if a wrapping key is currently set (with
   * {@link #wrapWith(Key)}), {@code false} otherwise.
   * <p>
   * This method will only be called if the driver declares
   * {@code wrapSupport=true} with {@link StoreDriverInfo}.
   */
  boolean isWrapping();
  
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
   * Saves the given key to the store. Any existing key will be silently
   * replaced, regardless of whether it is wrapped.
   * <p>
   * This method will never be called if the driver declares
   * {@code readOnly=true} with {@link StoreDriverInfo}.
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
   * @throws WrapKeyException if the stored key is wrapped and no wrap key
   *                          (or a wrong one) was specified, or the stored key
   *                          is NOT wrapped and a wrap key was specified.
   * @throws StoreException if there is some issue loading the stored data.
   */
  Key load() throws StoreException;
 
  /**
   * Erases any stored key, regardless of whether it is wrapped.
   * <p>
   * This method will never be called if the driver declares
   * {@code readOnly=true} with {@link StoreDriverInfo}.
   * 
   * @return {@code true} if, and only if, there was data present and it has
   *         been erased.
   * 
   * @throws StoreException if there is some issue erasing stored data.
   */
  boolean erase() throws StoreException;
}
