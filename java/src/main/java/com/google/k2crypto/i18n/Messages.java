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

package com.google.k2crypto.i18n;

import java.text.MessageFormat;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * Provides access to internationalized K2 message strings.
 * <p>
 * For a guide on how to use this framework, see the
 * <a href="http://docs.oracle.com/javase/tutorial/i18n/" target="_blank">Java
 * internationalization tutorial</a>.  
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public final class Messages {
  
  // Read: http://docs.oracle.com/javase/tutorial/i18n/
  
  private static final String BUNDLE_NAME = "com.google.k2crypto.i18n.messages";
  
  private static ResourceBundle resourceBundle = ResourceBundle.getBundle(BUNDLE_NAME);
  
  static {
    // Initialize locale with default
    //changeLocale(Locale.getDefault());
  }

  /**
   * Manually changes locale, for testing.
   * 
   * @param locale Locale to change to.
   */
  static void changeLocale(Locale locale) {
    resourceBundle = ResourceBundle.getBundle(BUNDLE_NAME, locale);
  }

  /**
   * Returns the named string formatted with the provided parameter values.
   * 
   * @param key Name of the string.
   * @param params Parameter values.
   * @return the formatted internationalized string, or {@code "!<key>!"} if
   *         the named string could not be found.
   */
  public static String getString(String key, Object ... params) {
    try {
      return MessageFormat.format(resourceBundle.getString(key), params);
    } catch (MissingResourceException ex) {
      // TODO: log this
      ex.printStackTrace();
    }
    return '!' + key + '!';
  }

  /**
   * Returns the named string.
   * 
   * @param key Name of the string.
   * @return the internationalized string, or {@code "!<key>!"} if
   *         the named string could not be found.
   */
  public static String getString(String key) {
    try {
      return resourceBundle.getString(key);
    } catch (MissingResourceException ex) {
      // TODO: log this
      ex.printStackTrace();
    }
    return '!' + key + '!';
  }
  
  // Non-instantiatable
  private Messages() {}

}