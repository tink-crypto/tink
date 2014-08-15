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

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.Locale;

/**
 * Unit tests for i18n strings.
 * 
 * These tests are non-language specific.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
@RunWith(JUnit4.class)
public class K2StringsTest {
  
  private static final String TEST_BUNDLE_NAME =
      "com.google.k2crypto.i18n.test_strings";

  /**
   * Tests getting a string keyed by a digit.
   */
  @Test public final void testDigitKey() {
    K2Strings strings =
        new K2Strings(null, TEST_BUNDLE_NAME, Locale.getDefault());
    String msg = strings.get("0");
    assertEquals("Number zero ", msg);
  }

  /**
   * Tests getting a string keyed by a letter.
   */
  @Test public final void testLetterKey() {
    K2Strings strings =
        new K2Strings(null, TEST_BUNDLE_NAME, Locale.getDefault());
    String msg = strings.get("a");
    assertEquals("Alphabet A  ", msg);
  }

  /**
   * Tests getting a multiline string.
   */
  @Test public final void testMultiline() {
    K2Strings strings =
        new K2Strings(null, TEST_BUNDLE_NAME, Locale.getDefault());
    String msg = strings.get("multiline");
    assertEquals("The quick brown fox jumps over the lazy dog", msg);
  }
  
  /**
   * Tests formatting a string with one parameter.
   */
  @Test public final void testFormatOne() {
    K2Strings strings =
        new K2Strings(null, TEST_BUNDLE_NAME, Locale.getDefault());
    assertEquals("I love dogs.", strings.get("one_param", "dogs"));
    assertEquals("I love cats.", strings.get("one_param", "cats"));    
  }
  
  /**
   * Tests formatting a string with two parameters.
   */
  @Test public final void testFormatTwo() {
    K2Strings strings = 
        new K2Strings(null, TEST_BUNDLE_NAME, Locale.getDefault());
    String msg = strings.get("two_params", "dogs", "cats");
    assertEquals("I love dogs and cats!", msg);
    msg = strings.get("two_params", "cats", "dogs");
    assertEquals("I love cats and dogs!", msg);
  }
}
