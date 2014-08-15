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

package com.google.k2crypto.storage.driver;

import java.lang.annotation.Documented;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Annotation applied to all {@link Driver} implementations.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
@Inherited
@Documented
@Retention(RetentionPolicy.RUNTIME)
public @interface DriverInfo {
  
  /**
   * Unique identifier of the driver, which users will specify in the scheme
   * portion of the URI address to a store.
   * 
   * <p>Legal identifiers must match the regular expression
   * {@code [a-z][a-z0-9\+\-\.]*}, which is identical to the pattern specified
   * in <a href="http://tools.ietf.org/html/rfc3986#section-3.1"
   * target="_blank">RFC 3986, Section 3.1</a> for a URI scheme, except that
   * upper-case letters are excluded.
   */
  String id();
  
  /**
   * Descriptive name of the driver.
   */
  String name();
  
  /**
   * Version string of the driver.
   */
  String version();
}
