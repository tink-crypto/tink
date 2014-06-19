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

import com.google.k2crypto.K2Exception;

/**
 * Exception thrown when there is an issue with an operation on a {@link Store}. 
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public class StoreException extends K2Exception {
  
  // Store that the exception occurred on
  private final Store store;
  
  /**
   * Constructs a new StoreException with the specified message.
   *
   * @param store The source of the exception. 
   * @param message The detail message.
   */
  public StoreException(Store store, String message) {
    super("[" + store.getAddress() + "] " + message);
    this.store = store;
  }
  
  /**
   * Constructs a new StoreException with the specified message and cause.
   *
   * @param store The source of the exception. 
   * @param message The detail message.
   * @param cause The cause of this exception.
   */
  public StoreException(Store store, String message, Throwable cause) {
    super("[" + store.getAddress() + "] " + message, cause);
    this.store = store;
  }
  
  /**
   * Returns the store that the exception occurred on.
   */
  public Store getStore() {
    return store;
  }
  
}
