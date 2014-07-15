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

package com.google.k2crypto.exceptions;

import com.google.k2crypto.K2Exception;
import com.google.k2crypto.Key;

/**
 * Exception thrown when the protobuf data for a {@link Key} is invalid. 
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public class InvalidKeyDataException extends K2Exception {

  /**
   * Reason why the InvalidKeyDataException was thrown. 
   */
  public static enum Reason {    
    /**
     * Some core bytes in the key could not be parsed as a protobuf.
     */
    PROTO_PARSE("Core cannot be parsed as a protobuf."),
    
    /**
     * A key version in the key failed to build. 
     */
    KEY_VERSION_BUILD("Key version failed to build."),
    
    /**
     * The pointer to the primary key version is wrong.
     */
    CORRUPTED_PRIMARY("The primary key version is corrupted.");

    final String message;
    
    private Reason(String message) {
      this.message = message;
    }
  }
  
  private final Reason reason;
  
  /**
   * Constructs a new InvalidKeyDataException.
   *
   * @param reason Reason the key or key version data is invalid.
   * @param cause The throwable that caused this.
   */
  public InvalidKeyDataException(Reason reason, Throwable cause) {
    super(reason.message, cause);
    this.reason = reason;
  }
  
  /**
   * Returns the reason the key or key version data is invalid. 
   */
  public Reason getReason() {
    return reason;
  }
}
