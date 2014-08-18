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
   * Reason why the IllegalAddressException was thrown. 
   */
  public static enum Reason {
    /**
     * The (string) address could not be parsed as a URI.
     */
    INVALID_URI("Address is not a valid URI."),
    
    /**
     * The address has a scheme component and the driver does not recognize it.
     */
    INVALID_SCHEME("Address scheme is invalid."),

    /**
     * The address does not have a valid path
     * (typically for file-system-based drivers).
     */
    INVALID_PATH("Address does not have a valid path."),
    
    /**
     * The address query is unrecognized or invalid.
     */
    INVALID_QUERY("Address does not have a valid query."),

    /**
     * The address fragment is unrecognized or invalid.
     */
    INVALID_FRAGMENT("Address does not have a valid fragment."),
    
    /**
     * The address does not have the required host/port components.
     * (typically for network-based drivers).
     */
    MISSING_HOST_PORT("Address does not have a host/port."),

    /**
     * The address does not have the required path
     * (typically for file-system-based drivers).
     */
    MISSING_PATH("Address does not have a path."),

    /**
     * The address does not have the required query.
     */
    MISSING_QUERY("Address does not have a query."),

    /**
     * The address does not have the required fragment.
     */
    MISSING_FRAGMENT("Address does not have a fragment."),
    
    /**
     * The address has a user component and the driver does not support it.
     */
    USER_UNSUPPORTED("User component is unsupported."),

    /**
     * The address has host/port components and the driver does not support it.
     */
    HOST_PORT_UNSUPPORTED("Host/port components are unsupported."),

    /**
     * The address has an authority component (i.e. user, host and/or port) and
     * the driver does not support it.
     */
    AUTHORITY_UNSUPPORTED("Authority component is unsupported."),

    /**
     * The address has a path component and the driver does not support it.
     */
    PATH_UNSUPPORTED("Path component is unsupported."),

    /**
     * The address has a query component and the driver does not support it.
     */
    QUERY_UNSUPPORTED("Query component is unsupported."),

    /**
     * The address has a fragment component and the driver does not support it.
     */
    FRAGMENT_UNSUPPORTED("Fragment component is unsupported."),

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
  public IllegalAddressException(
      String address, Reason reason, Throwable cause) {
    this(address, reason, null, cause);
  }

  /**
   * Constructs a new IllegalAddressException.
   *
   * @param address The illegal URI address.
   * @param reason Reason why the address is illegal.
   * @param cause The throwable that caused this one.
   */
  public IllegalAddressException(
      URI address, Reason reason, Throwable cause) {
    this(address.toASCIIString(), reason, null, cause);
  }

  /**
   * Constructs a new IllegalAddressException with driver-specific details.
   *
   * @param address The illegal URI address.
   * @param details Driver-specific details.
   * @param cause The throwable that caused this one.
   */
  public IllegalAddressException(
      URI address, String details, Throwable cause) {
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
  private IllegalAddressException(
      String address, Reason reason, String details, Throwable cause) {
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
