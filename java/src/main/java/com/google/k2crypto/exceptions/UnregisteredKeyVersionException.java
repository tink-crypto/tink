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
import com.google.k2crypto.keyversions.KeyVersionProto.Type;

/**
 * Exception thrown when a required KeyVersion type is unregistered.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public class UnregisteredKeyVersionException extends K2Exception {
  
  private final Type type;
  
  /**
   * Constructs a new UnregisteredKeyVersionException.
   *
   * @param type Type requested but not registered.
   */
  public UnregisteredKeyVersionException(Type type) {
    super(type.name());
    this.type = type;
  }
  
  /**
   * Returns the unregistered type.
   */
  public Type getType() {
    return type;
  }
}
