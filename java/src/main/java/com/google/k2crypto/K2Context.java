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

package com.google.k2crypto;

import com.google.k2crypto.i18n.K2Strings;
import com.google.k2crypto.keyversions.KeyVersionRegistry;

import java.util.Locale;

/**
 * Context that will be propagated to every object in a K2 session. 
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public class K2Context {
  /*
   * NOTE: The design of this class is subject to heavy revision.
   *       The current implementation only serves to bootstrap K2 dev.
   */
  
  // Internationalized strings
  private K2Strings strings; 
  
  // Registry for all available key versions
  private KeyVersionRegistry keyVersionRegistry;
  
  /**
   * Constructs a new K2 context.
   */
  public K2Context() {
    strings = new K2Strings(this, Locale.getDefault());
    keyVersionRegistry = new KeyVersionRegistry(this);
  }
  
  /**
   * Returns the interface for obtaining internationalized strings.
   */
  public K2Strings getStrings() {
    return strings;
  }
  
  /**
   * Returns the registry of all available key versions.
   */
  public KeyVersionRegistry getKeyVersionRegistry() {
    return keyVersionRegistry;
  }
}
