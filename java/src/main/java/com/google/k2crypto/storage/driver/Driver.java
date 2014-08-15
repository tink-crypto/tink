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

package com.google.k2crypto.storage.driver;

import com.google.k2crypto.K2Context;
import com.google.k2crypto.storage.IllegalAddressException;
import com.google.k2crypto.storage.Store;
import com.google.k2crypto.storage.StoreException;

import java.net.URI;

/**
 * Main driver interface for a key storage location.
 * 
 * <p>Drivers are concrete implementations of a {@link Store}. In addition to
 * implementing this interface, the instantiatable driver class must be
 * annotated with {@link DriverInfo}, provide a public constructor
 * with no arguments and implement {@link ReadableDriver} and/or
 * {@link WritableDriver} depending on the operations supported. For example,
 * a driver that only allows importing of Keys would only implement
 * {@link ReadableDriver}. The {@link WrappingDriver} interface should be 
 * implemented for drivers that support wrapping/unwrapping of Keys.
 *    
 * <p>When instantiated, {@link #initialize(K2Context)} will be invoked on the
 * driver to provide the context of the current K2 session. After a successful
 * initialization, {@link #open(URI)} will be called to actually allocate
 * resources for performing storage operations on the specified storage address.
 * This method may throw {@link IllegalAddressException} if the address is not
 * recognized by the driver. Finally, {@link #close()} will be called to free
 * resources, after the user has performed the storage operations. Note that it
 * is NOT safe to allocate resources before {@link #open(URI)} is called,
 * e.g. during construction or on initialize.
 * 
 * <p>Drivers need not be concerned with thread safety, or methods invoked when
 * they are not supported, or methods invoked when {@link #open(URI)} has not
 * been called, or methods invoked when {@link #close()} has been called. The
 * {@link Store} wrapper will manage all access to the driver by ensuring that
 * calls are synchronized, methods are not invoked when inappropriate, etc.
 *  
 * <p>A note about open/close and network-based stores: It is possible for the
 * network connection to drop after the driver is opened. However, the driver
 * must not implicitly close the store in this event. As long as the store is
 * still open, the connection should be reattempted.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public interface Driver {

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
   * 
   * <p>An open may fail if the address is illegal with respect to the driver
   * implementation; e.g. it contains invalid characters that will not map
   * to any file-system. An open may also fail if the provided address is legal
   * but points to an unsuitable location; e.g. it contains existing files not
   * recognizable by the driver or points to a location that is not
   * readable/writable. Note that in the first case, resources need not be
   * allocated, while in the second case, files might need to be opened to
   * verify that the location is valid. Either way, if an open fails, the
   * driver must ensure that any partially allocated resources are freed;
   * {@link #close()} will not be called if {@code open()} throws an exception.
   * The driver can assume that {@code open()} will not be called again if it
   * fails.
   * 
   * <p>This method may also return a modified address to present to the user,
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
}
