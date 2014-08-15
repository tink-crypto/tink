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

package com.google.k2crypto.i18n;

import com.google.k2crypto.K2Context;

import java.text.MessageFormat;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * Provides access to internationalized K2 strings.
 * 
 * <p>For a guide on how to use this framework, see the
 * <a href="http://docs.oracle.com/javase/tutorial/i18n/" target="_blank">Java
 * internationalization tutorial</a>.  
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public class K2Strings {
  
  /**
   * Default resource bundle name.
   */
  public static final String DEFAULT_BUNDLE_NAME =
      "com.google.k2crypto.i18n.strings";
  
  // Context for logging purposes (can be null for testing)
  private final K2Context context;

  // Bundle to pull the strings from
  private final ResourceBundle resourceBundle;
  
  // Name of the bundle, for debugging
  private final String bundleName;
  
  /**
   * Constructs a set of K2 strings populated from the default locale-specific
   * resource bundle.
   * 
   * @param context Context for logging, or null if not available.
   * @param locale Locale of the string resources.
   */
  public K2Strings(K2Context context, Locale locale) {
    this(context, DEFAULT_BUNDLE_NAME, locale);
  }
  
  /**
   * Constructs a set of K2 strings populated from a locale-specific 
   * resource bundle.
   * 
   * @param context Context for logging, or null if not available.
   * @param bundleName Name of the resource bundle to load.
   * @param locale Locale of the string resources.
   */
  public K2Strings(K2Context context, String bundleName, Locale locale) {
    this.context = context;
    this.bundleName = bundleName;
    resourceBundle = ResourceBundle.getBundle(bundleName, locale);
  }
  
  /**
   * Returns the context associated with the strings.
   */
  public K2Context getContext() {
    return context;
  }
  
  /**
   * Overridable handler for requests for a missing resource.
   * 
   * @param ex Exception containing information about the resource request.
   * @return an alternative string, if possible.
   */
  protected String handleMissing(MissingResourceException ex) {
    throw new AssertionError("Missing resource: " + ex.getKey(), ex);
  }
  
  /**
   * Returns the named string formatted with the provided parameter values.
   * 
   * @param key Name of the string.
   * @param params Parameter values.
   * @return the formatted internationalized string.
   * 
   * @throws AssertionError (by default) if the string is not found.
   */
  public String get(String key, Object ... params) {
    try {
      return MessageFormat.format(resourceBundle.getString(key), params);
    } catch (MissingResourceException ex) {
      return handleMissing(ex);
    }
  }

  /**
   * Returns the named string.
   * 
   * @param key Name of the string.
   * @return the internationalized string.
   * 
   * @throws AssertionError (by default) if the string is not found.
   */
  public String get(String key) {
    try {
      return resourceBundle.getString(key);
    } catch (MissingResourceException ex) {
      return handleMissing(ex);
    }
  }
  
  /**
   * Returns the bundle name and language.
   */
  @Override
  public String toString() {
    return bundleName + '[' + resourceBundle.getLocale().getLanguage() + ']';
  }
}
