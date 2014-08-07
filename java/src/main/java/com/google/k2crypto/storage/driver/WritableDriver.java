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
 * Interface implemented on a driver that supports writing of keys. 
 * 
 * @see Driver
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public interface WritableDriver {

  /**
   * Saves the given key to the store. Any existing key will be silently
   * replaced, regardless of whether it is wrapped.
   *  
   * @param key Key to save.
   * 
   * @throws StoreIOException if there is an I/O issue with saving the key.
   * @throws StoreException if there is some issue saving the given key.
   */
  void save(Key key) throws StoreException;
    
  /**
   * Erases any stored key, regardless of whether it is wrapped.
   * 
   * @return {@code true} if, and only if, there was data present and it has
   *         been erased.
   * 
   * @throws StoreIOException if there is an I/O issue with erasing the key.
   * @throws StoreException if there is some issue erasing stored data.
   */
  boolean erase() throws StoreException;
}
