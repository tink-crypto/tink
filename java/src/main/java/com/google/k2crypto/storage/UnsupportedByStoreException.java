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

/**
 * Exception thrown when the operation invoked is unsupported by the store. 
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public class UnsupportedByStoreException extends StoreException {
  
  /**
   * Constructs a new UnsupportedByStoreException with the specified message.
   *
   * @param message the detail message.
   */
  public UnsupportedByStoreException(String message) {
    super(message);
  }
}
