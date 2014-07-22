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

package com.google.k2crypto.keyversions;

import java.lang.annotation.Documented;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Annotation applied to all {@link KeyVersion} implementations.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
@Inherited
@Documented
@Retention(RetentionPolicy.RUNTIME)
public @interface KeyVersionInfo {
  
  /**
   * Type of the Key Version, as listed in {@code key_version.proto}.
   */
  KeyVersionProto.Type type();

  /**
   * Generated protocol buffer class of the key version that contains the
   * data and core messages.
   */
  Class<?> proto();
}
