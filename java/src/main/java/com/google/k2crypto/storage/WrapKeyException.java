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

import com.google.k2crypto.Key;

/**
 * Exception thrown when a operation cannot be performed because a stored
 * {@link Key} is wrapped (encrypted).
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public class WrapKeyException extends StoreException {

  /**
   * Reason why the WrapKeyException was thrown. 
   */
  public static enum Reason {
    /**
     * A wrap key is required, and was not provided. 
     */
    REQUIRED("A wrap key is required."),
    
    /**
     * A wrap key was provided, but is not needed. 
     */
    UNNECESSARY("The wrap key is not required."),

    /**
     * The provided wrap key cannot unwrap the stored key.
     */
    WRONG("The provided wrap key is wrong.");
    
    final String message;
    
    private Reason(String message) {
      this.message = message;
    }
  }
  
  private final Reason reason;
  
  /**
   * Constructs a new WrapKeyException.
   *
   * @param reason The reason for the exception.
   */
  public WrapKeyException(Reason reason) {
    super(reason.message);
    this.reason = reason;
  }
  
  /**
   * Returns the reason for the exception. 
   */
  public Reason getReason() {
    return reason;
  }
}
