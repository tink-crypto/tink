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
 * Exception thrown when there is no suitable driver for accessing a specified
 * storage address.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public class NoSuitableDriverException extends K2Exception {
        
  private final URI address;
  
  /**
   * Constructs a new NoSuitableDriverException.
   *
   * @param address The location that could not be accessed.
   */
  public NoSuitableDriverException(URI address) {
    super(address.toString());
    this.address = address;
  }
  
  /**
   * Returns the location that could not be accessed.
   */
  public URI getAddress() {
    return address;
  }
}
