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

package com.google.k2crypto;

import static org.junit.Assert.assertEquals;

import com.google.k2crypto.Placeholdermessage.PlaceholderMessage;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.UnsupportedEncodingException;

/** Unit tests for {@link Placeholder}. */
@RunWith(JUnit4.class)
public class PlaceholderTest {

  @Before public void setUp() {
  }

  @Test public void testSomething() throws UnsupportedEncodingException {
    PlaceholderMessage message = new Placeholder().getSomething();
    assertEquals("Something else!", 1, message.getVersion());
    assertEquals("Something else again!",
        "something", message.getPayload().toString("UTF-8"));
  }
}
