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

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for K2Exception. 
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
@RunWith(JUnit4.class)
public class K2ExceptionTest {
  
  private static final String MESSAGE =
      "This is an exceptionally exceptional exception message.";
  
  private static final Throwable CAUSE =
      new Throwable("This is the cause of the exception.");
  
  /**
   * Tests construction with a message.
   */
  @Test public void testMessage() {
    K2Exception ex = new K2Exception(MESSAGE);
    assertEquals("Expect same message", MESSAGE, ex.getMessage());
  }
  
  /**
   * Tests construction with a message and cause.
   */
  @Test public void testMessageCause() {
    K2Exception ex = new K2Exception(MESSAGE, CAUSE);
    assertEquals("Expect same message", MESSAGE, ex.getMessage());
    assertEquals("Expect same cause", CAUSE, ex.getCause());
  }
  
}
