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

import com.google.k2crypto.K2Exception;

import java.net.URI;

/**
 * Exception thrown when a given String or URI is not a valid storage address.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public class IllegalAddressException extends K2Exception {

  /**
   * Reason why the exception was thrown. 
   */
  public static enum Reason {
    /**
     * The address has no path. 
     */
    NO_PATH("Address requires a path."),
    
    /**
     * The address has no scheme.
     */
    NO_SCHEME("Address requires a scheme."),
    
    /**
     * The (string) address could not be parsed as a URI.
     */
    INVALID_URI("Address is not a valid URI."),
    
    /**
     * The address was rejected for a driver-specific reason.
     */
    DRIVER_SPECIFIC("Address was rejected by the driver.");

    final String message;
    
    private Reason(String message) {
      this.message = message;
    }
  }
  
  private final String address;
  
  private final Reason reason;
  
  private final String details;
  
  /**
   * Constructs a new IllegalAddressException.
   *
   * @param address The illegal string address.
   * @param reason Reason why the address is illegal.
   * @param cause The throwable that caused this one.
   */
  public IllegalAddressException(String address, Reason reason,
      Throwable cause) {
    this(address, reason, null, cause);
  }

  /**
   * Constructs a new IllegalAddressException.
   *
   * @param address The illegal URI address.
   * @param reason Reason why the address is illegal.
   * @param cause The throwable that caused this one.
   */
  public IllegalAddressException(URI address, Reason reason,
      Throwable cause) {
    this(address.toASCIIString(), reason, null, cause);
  }

  /**
   * Constructs a new IllegalAddressException with driver-specific details.
   *
   * @param address The illegal URI address.
   * @param details Driver-specific details.
   * @param cause The throwable that caused this one.
   */
  public IllegalAddressException(URI address, String details,
      Throwable cause) {
    this(address.toASCIIString(), Reason.DRIVER_SPECIFIC, details, cause);
  }

  /**
   * Constructs a new IllegalAddressException.
   *
   * @param address The illegal address.
   * @param reason Reason why the address is illegal.
   * @param details Driver-specific details.
   * @param cause The throwable that caused this one.
   */
  private IllegalAddressException(String address, Reason reason,
      String details, Throwable cause) {
    super(reason.message, cause);
    this.address = address;
    this.reason = reason;
    this.details = details;
  }
  
  /**
   * Returns the illegal address.
   */
  public String getAddress() {
    return address;
  }
  
  /**
   * Returns the reason why the address is illegal.
   */
  public Reason getReason() {
    return reason;
  }
  
  /**
   * Returns driver-specific details for why the address was rejected.
   */
  public String getDetails() {
    return details;
  }
}
