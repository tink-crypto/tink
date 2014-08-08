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

/**
 * Interface implemented on a driver that supports wrapping/encryption of keys. 
 * 
 * @see Driver
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public interface WrappingDriver {

  /**
   * Indicates that subsequent saves/loads on this store should be
   * wrapped/unwrapped with the provided key.
   * 
   * <p>The driver should, in its initial state, have no wrapping key set.
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
   */
  boolean isWrapping();
}
