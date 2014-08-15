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
import com.google.k2crypto.keyversions.KeyVersion;
import com.google.k2crypto.keyversions.KeyVersion.Builder;
import com.google.k2crypto.keyversions.KeyVersionInfo;

/**
 * Exception thrown when there is a problem with the structure of a
 * key version implementation.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public class KeyVersionException extends K2Exception {
  
  /**
   * Reason why the KeyVersionException was thrown. 
   */
  public static enum Reason {
    /**
     * The key version class does not have a Builder as an inner-class.
     */
    NO_BUILDER("Builder class is missing."),

    /**
     * The builder class does not extend {@link Builder}.
     */
    BAD_PARENT("Builder class does not extend KeyVersion.Builder."),
    
    /**
     * The builder class does not have a {@code build()} method
     * returning the expected key version type. 
     */
    BAD_BUILD("Builder class does not build the specified KeyVersion."),

    /**
     * The builder class does not have an accessible no-argument constructor.
     */
    NO_CONSTRUCTOR("Builder is missing an accessible constructor."),

    /**
     * The builder could not be instantiated.
     */
    INSTANTIATE_FAIL("Builder failed to instantiate."),

    /**
     * The builder constructor declares throwables that extend classes other
     * than Error or RuntimeException.
     */
    ILLEGAL_THROWS("Builder constructor throws illegal throwables."),

    /**
     * The key version class is not annotated with {@link KeyVersionInfo}.
     */
    NO_METADATA("Key version is missing meta-data annotation."),
    
    /**
     * The annotation-declared proto class does not appear to be a generated
     * proto.
     */
    BAD_PROTO("The provided proto class does not look like a proto.");

    final String message;
    
    private Reason(String message) {
      this.message = message;
    }
  }
      
  private final Class<? extends KeyVersion> keyVersionClass;

  private final Reason reason;
  
  /**
   * Constructs a new KeyVersionException.
   *
   * @param keyVersionClass Class of the problematic key version.
   * @param reason The reason the key version is problematic.
   */
  public KeyVersionException(
      Class<? extends KeyVersion> keyVersionClass, Reason reason) {
    super(reason.message);
    this.keyVersionClass = keyVersionClass;
    this.reason = reason;
  }
  
  /**
   * Returns the class of the problematic key version.
   */
  public Class<? extends KeyVersion> getKeyVersionClass() {
    return keyVersionClass;
  }
  
  /**
   * Returns the reason the key version is problematic. 
   */
  public Reason getReason() {
    return reason;
  }
}
