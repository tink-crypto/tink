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
 * Exception thrown when a store operation cannot be performed because of an
 * I/O or serialization/deserialization issue.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public class StoreIOException extends StoreException {

  /**
   * Reason why the StoreIOException was thrown. 
   */
  public static enum Reason {
    // NOTE: these reasons are specifically ordered from high-level to low-level
    
    /**
     * A key version cannot be read because it is unregistered.
     * This is possibly a configuration error.
     */
    UNREGISTERED_KEY_VERSION("A key version is unregistered."),

    /**
     * The key could not be serialized to bytes.
     */
    SERIALIZATION_ERROR("The key could not be serialized."),

    /**
     * The read bytes could not be parsed as a key. 
     */
    DESERIALIZATION_ERROR("The key could not be deserialized/parsed."),

    /**
     * A wrap key is required, and was not provided. 
     */
    WRAP_KEY_REQUIRED("A wrap key is required."),
    
    /**
     * The provided wrap key cannot unwrap the stored key.
     */
    WRAP_KEY_WRONG("The provided wrap key is wrong."),

    /**
     * A wrap key was provided, but is not needed. 
     */
    WRAP_KEY_UNNECESSARY("The wrap key is not required."),

    /**
     * Error writing to a device/resource.
     */
    WRITE_ERROR("General write error."),
    
    /**
     * Error reading from a device/resource.
     */
    READ_ERROR("General read error."),
    
    /**
     * The key being read or written is too large for the driver to handle.
     */
    KEY_TOO_LARGE("Key is too large."),

    /**
     * Driver-specific error when reading/writing the key.
     */
    DRIVER_SPECIFIC("Driver-specific I/O error.");
    
    final String message;
    
    private Reason(String message) {
      this.message = message;
    }
  }
  
  private final Reason reason;
  
  /**
   * Constructs a new StoreIOException.
   *
   * @param reason The reason for the exception.
   */
  public StoreIOException(Reason reason) {
    super(reason.message);
    this.reason = reason;
  }
  
  /**
   * Constructs a new StoreIOException with a cause.
   *
   * @param reason The reason for the exception.
   * @param cause Cause of this exception.
   */
  public StoreIOException(Reason reason, Throwable cause) {
    super(reason.message, cause);
    this.reason = reason;
  }
  
  /**
   * Returns the reason for the exception. 
   */
  public Reason getReason() {
    return reason;
  }
}
