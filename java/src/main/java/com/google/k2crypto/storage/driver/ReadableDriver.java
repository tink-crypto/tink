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

import com.google.k2crypto.Key;
import com.google.k2crypto.storage.StoreException;
import com.google.k2crypto.storage.StoreIOException;

/**
 * Interface implemented on a driver that supports reading of keys. 
 * 
 * @see Driver
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public interface ReadableDriver {
  
  /**
   * Returns {@code true} if there is no key stored at this location,
   * {@code false} if one might be present.
   * 
   * <p>Note that if this method returns false, there is no a guarantee that the
   * key will actually be readable. The data might be encrypted, corrupted
   * or be in an invalid format. An attempt must be made to {@link #load()} to
   * know for sure if it is readable.
   * 
   * @throws StoreIOException if there is an I/O issue with checking emptiness.
   * @throws StoreException if the store could not be queried.
   */
  boolean isEmpty() throws StoreException;
        
  /**
   * Loads the key stored at this location. 
   * 
   * @return the stored key or null if the location is empty.
   * 
   * @throws StoreIOException if there is an I/O issue with loading the key.
   * @throws StoreException if there is some issue loading the stored data.
   */
  Key load() throws StoreException;
}
