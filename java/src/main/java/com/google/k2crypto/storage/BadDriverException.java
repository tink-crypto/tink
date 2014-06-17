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
 * Exception thrown when a badly-implemented driver is detected.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public class BadDriverException extends K2Exception {

  // Bad, bad driver
  private final Class<? extends StoreDriver> driverClass;
  
  /**
   * Constructs a new BadDriverException.
   *
   * @param driverClass Class of the bad driver.
   * @param reason The reason the driver is bad.
   */
  public BadDriverException(
      Class<? extends StoreDriver> driverClass, String reason) {
    super(reason);
    this.driverClass = driverClass;
  }
  
  /**
   * Returns the class of the bad driver.
   */
  public Class<? extends StoreDriver> getDriverClass() {
    return driverClass;
  }
  
  /**
   * Returns the reason the driver is bad. 
   */
  public String getReason() {
    return getMessage();
  }
  
}