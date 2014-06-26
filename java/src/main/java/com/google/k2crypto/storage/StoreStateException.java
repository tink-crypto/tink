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
 * Exception thrown when the store is in a state unsuitable for the operation. 
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public class StoreStateException extends StoreException {

  /**
   * Reason why the StoreStateException was thrown. 
   */
  public static enum Reason {
    /**
     * The store cannot perform the operation because it is not open. 
     */
    NOT_OPEN("Store not open."),
    
    /**
     * The store is already open.
     */
    ALREADY_OPEN("Store already open."),
    
    /**
     * The store is already closed.
     */
    ALREADY_CLOSED("Store already closed.");
    
    final String message;
    
    private Reason(String message) {
      this.message = message;
    }
  }
  
  private final Reason reason;

  /**
   * Constructs a new StoreStateException.
   *
   * @param reason The reason for the exception.
   */
  public StoreStateException(Reason reason) {
    super(reason.message);
    this.reason = reason;
  }

  /**
   * Returns the reason for the state exception. 
   */
  public Reason getReason() {
    return reason;
  }
}
