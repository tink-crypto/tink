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

package com.google.k2crypto.storage.driver.impl;

import static com.google.k2crypto.storage.driver.AddressUtilities.checkNoAuthority;
import static com.google.k2crypto.storage.driver.AddressUtilities.checkNoQuery;
import static com.google.k2crypto.storage.driver.AddressUtilities.checkNoFragment;
import static com.google.k2crypto.storage.driver.AddressUtilities.extractRawPath;

import com.google.k2crypto.Key;
import com.google.k2crypto.K2Context;
import com.google.k2crypto.KeyProto.KeyData;
import com.google.k2crypto.exceptions.InvalidKeyDataException;
import com.google.k2crypto.exceptions.UnregisteredKeyVersionException;
import com.google.k2crypto.storage.IllegalAddressException;
import com.google.k2crypto.storage.StoreException;
import com.google.k2crypto.storage.StoreIOException;
import com.google.k2crypto.storage.driver.ReadableDriver;
import com.google.k2crypto.storage.driver.Driver;
import com.google.k2crypto.storage.driver.DriverInfo;
import com.google.k2crypto.storage.driver.WritableDriver;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

/**
 * K2-native in-memory (i.e. volatile) key storage driver.
 * 
 * <p>This driver uses the normalized path component of the storage address
 * to uniquely identify the memory slot for saving or loading the key. In other
 * words, a key stored at a certain address can be retrieved at a later time 
 * as long as the same logical address is used. Stored keys are retained only
 * for the lifetime of the Java virtual machine.
 *  
 * <p>The driver accepts storage addresses only in the following format:
 * {@code [mem:]{ANY LEGAL URI PATH}}
 *
 * @author darylseah@gmail.com (Daryl Seah)
 */
@DriverInfo(
    id = K2MemoryDriver.NATIVE_SCHEME,
    name = "K2 Native Memory Driver",
    version = "0.1")
public class K2MemoryDriver implements Driver, ReadableDriver, WritableDriver {
  
  /**
   * Name of the native scheme in use (also the identifier of the driver).
   */
  static final String NATIVE_SCHEME = "mem";
  
  // Memory space that will be shared among all driver instances
  private static final MemorySpace sharedMemorySpace = new MemorySpace();

  // Context for the current K2 session
  private K2Context context;

  // Address of the storage slot in the memory space
  private URI address;
  
  // Memory space associated with the current driver session
  private MemorySpace memSpace;
  
  /**
   * @see Driver#initialize(K2Context)
   */
  public void initialize(K2Context context) {
    this.context = context;
  }

  /**
   * @see Driver#open(java.net.URI)
   */
  public URI open(final URI address) throws IllegalAddressException {
    // Check for unsupported components in the address and scheme.
    // (we only accept a scheme + path + optional fragment)
    checkNoAuthority(address);
    checkNoQuery(address);
    checkNoFragment(address);
    checkScheme(address);
    
    // Extract normalized path
    String path = extractRawPath(address.normalize());
    
    // Reconstitute final address
    StringBuilder sb =
        new StringBuilder(2 + NATIVE_SCHEME.length() + path.length());
    sb.append(NATIVE_SCHEME).append(':');
    if (path.charAt(0) != '/') {
      sb.append('/');
    }
    sb.append(path);
    URI normAddress = URI.create(sb.toString());
    this.address = normAddress;    
    
    // Assign memory space to use (currently just shared among all instances)
    memSpace = sharedMemorySpace;
    return normAddress;
  }
  
  /**
   * Checks that there is no scheme or that the scheme is identical to the 
   * driver identifier.
   *  
   * @param address Address to check.
   * 
   * @throws IllegalAddressException if the address has an invalid scheme.
   */
  private void checkScheme(URI address) throws IllegalAddressException {
    String scheme = address.getScheme();
    if (scheme != null && !NATIVE_SCHEME.equalsIgnoreCase(scheme)) {
      // Unrecognized scheme
      throw new IllegalAddressException(
          address, IllegalAddressException.Reason.INVALID_SCHEME, null);
    }
  }
  
  /**
   * @see Driver#close()
   */
  public void close() {
    // Free resources.
    context = null;
    address = null;
    memSpace = null;
  }

  /**
   * @see ReadableDriver#isEmpty()
   */
  public boolean isEmpty() throws StoreException {
    return memSpace.isEmpty(address);
  }

  /**
   * @see WritableDriver#save(Key)
   */
  public void save(Key key) throws StoreException {
    KeyData data;
    try {
      data = key.buildData().build();
    } catch (RuntimeException ex) {
      throw new StoreIOException(
          StoreIOException.Reason.SERIALIZATION_ERROR, ex);
    }
    memSpace.save(address, data);
  }
  
  /**
   * @see ReadableDriver#load()
   */
  public Key load() throws StoreException {
    KeyData data = memSpace.load(address);
    if (data == null) {
      return null;
    }
    try {
      return new Key(context, data);
    } catch (InvalidKeyDataException ex) {
      throw new StoreIOException(
          StoreIOException.Reason.DESERIALIZATION_ERROR, ex);
    } catch (UnregisteredKeyVersionException ex) {
      throw new StoreIOException(
          StoreIOException.Reason.UNREGISTERED_KEY_VERSION, ex);
    }
  }
  
  /**
   * @see WritableDriver#erase()
   */
  public boolean erase() throws StoreException {
    return memSpace.erase(address);
  }
  
  /**
   * A memory-based key storage space.
   * 
   * <p>All methods synchronize directly on the object for thread-safety.
   * Should be acceptable since it is private to the driver.    
   */
  private static final class MemorySpace {
    // Storage is simply a mapping from addresses to key proto data  
    private final Map<URI, KeyData> slots = new HashMap<URI, KeyData>();
    
    /** Back-end for {@code ReadableDriver#isEmpty()}. */
    synchronized boolean isEmpty(URI address) {
      return !slots.containsKey(address);
    }
    
    /** Back-end for {@code ReadableDriver#load()}. */
    synchronized KeyData load(URI address) {
      return slots.get(address);
    }

    /** Back-end for {@code WritableDriver#save(Key)}. */
    synchronized void save(URI address, KeyData data) {
      slots.put(address, data);
    }
    
    /** Back-end for {@code WritableDriver#erase()}. */
    synchronized boolean erase(URI address) {
      return slots.remove(address) != null;
    }
  }  
}
