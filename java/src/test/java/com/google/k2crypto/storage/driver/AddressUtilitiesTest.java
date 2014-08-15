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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.k2crypto.storage.IllegalAddressException;

import java.net.URI;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for the address utility methods.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
@RunWith(JUnit4.class)
public class AddressUtilitiesTest {
  
  /**
   * Tests the encodeConvenience(String) method.
   */
  @Test public final void testEncodeConvenience() {
    // Check empty string
    assertEquals("", AddressUtilities.encodeConvenience(""));
    
    // Substrings that are invariant on encoding
    final String[] identities = {
        "a", "A", "9", "%20", "%25", "%fA", "%Af", "%09", "%90", "%0A", "%a9"
    };
    
    // Check identity encodings and 2-up sequences
    for (String id : identities) {
      assertEquals(id, AddressUtilities.encodeConvenience(id));
      for (String id2 : identities) {
        String tmp = id + id2;
        assertEquals(tmp, AddressUtilities.encodeConvenience(tmp));
      }
    }
    
    // Input substrings and encoded results 
    final String[] input = {
        "", " ",   "%",   "%G",   "%g",   "%0G",   "%0g"
    };
    final String[] encoded = {
        "", "%20", "%25", "%25G", "%25g", "%250G", "%250g"
    };
    assertEquals(input.length, encoded.length);
    
    // Check individual encoded results and 2-up sequences
    // (exclude initial empty string)
    for (int i = 1; i < input.length; ++i) {
      assertEquals(encoded[i], AddressUtilities.encodeConvenience(input[i]));
      for (int j = 1; j < input.length; ++j) {
        String tmpInput = input[i] + input[j];
        String tmpExpected = encoded[i] + encoded[j];
        assertEquals(tmpExpected, AddressUtilities.encodeConvenience(tmpInput));
      }
    }

    // Check various permutations
    for (String id : identities) {
      for (int i = 0; i < input.length; ++i) {
        for (int j = 0; j < input.length; ++j) {
          assertEquals(
              encoded[i] + id + encoded[j],
              AddressUtilities.encodeConvenience(input[i] + id + input[j]));
        }
      }
    }
  }
  
  /**
   * Tests the decodeUnreserved(String) and decodeUnreserved(URI) methods.
   */
  @Test public final void testDecodeUnreserved() {
    // Check decoding of all extreme unreserved cases
    assertEquals("--..__~~09",
        AddressUtilities.decodeUnreserved("%2D%2d%2E%2e%5F%5f%7E%7e%30%39"));
    assertEquals("AIJJOOPYZZ",
        AddressUtilities.decodeUnreserved("%41%49%4A%4a%4F%4f%50%59%5A%5a"));
    assertEquals("aijjoopyzz",
        AddressUtilities.decodeUnreserved("%61%69%6A%6a%6F%6f%70%79%7A%7a"));
    
    // Check that values just beyond unreserved ranges are not decoded
    String identity = "%40%5B %60%7B %2F%3A";
    assertEquals(identity, AddressUtilities.decodeUnreserved(identity));
    identity = identity.toLowerCase();
    assertEquals(identity, AddressUtilities.decodeUnreserved(identity));
    
    // In particular, reserved and invalid characters MUST NOT be decoded
    // because they can change how (or whether) the URI is interpreted 
    identity = "%21%23%24%26%27%28%29%2A%2B%2C%2F%3A%3B%3D%3F%40%5B%5D %20%25";
    assertEquals(identity, AddressUtilities.decodeUnreserved(identity));
    identity = identity.toLowerCase();
    assertEquals(identity, AddressUtilities.decodeUnreserved(identity));
    
    // The URI version of the method should just direct to the string version,
    // but we do a broad test just to make sure.
    assertEquals(
        URI.create("k2://h%2F/%3f%23/../~/./key"),
        AddressUtilities.decodeUnreserved(
            URI.create("k2://%68%2F/%3f%23/%2e%2E/%7e/%2E/%6bey")));
  }

  /**
   * Tests the checkNoAuthority(URI) method.
   */
  @Test public final void testCheckNoAuthority() {
    // Acceptance cases
    for (String address : new String[] {
        "k2:///p?q#f", "/p?q#f", "///p", ""
    }) {
      try {
        AddressUtilities.checkNoAuthority(URI.create(address));
      } catch (IllegalAddressException ex) {
        fail("Address is acceptable: " + address);
      }
    }
    // Rejection cases
    for (String address : new String[] {
        "k2://u@h:1", "//:1", "//u@", "//h"
    }) {
      try {
        AddressUtilities.checkNoAuthority(URI.create(address));
        fail("Should reject " + address);
      } catch (IllegalAddressException expected) {
        assertEquals(address, expected.getAddress());
        assertEquals(
            IllegalAddressException.Reason.AUTHORITY_UNSUPPORTED,
            expected.getReason());
      }
    }
  }
  
  /**
   * Tests the checkNoUser(URI) method.
   */
  @Test public final void testCheckNoUser() {
    // Acceptance cases
    for (String address : new String[] {
        "k2://h:1/p?q#f", "//@h:1", "@h", ""
    }) {
      try {
        AddressUtilities.checkNoUser(URI.create(address));
      } catch (IllegalAddressException ex) {
        fail("Address is acceptable: " + address);
      }
    }
    // Rejection cases
    for (String address : new String[] {
        "k2://u@h:1", "//u@h"
        // NOTE: a user alone (e.g. "//u@") does not get parsed without a host
    }) {
      try {
        AddressUtilities.checkNoUser(URI.create(address));
        fail("Should reject " + address);
      } catch (IllegalAddressException expected) {
        assertEquals(address, expected.getAddress());
        assertEquals(
            IllegalAddressException.Reason.USER_UNSUPPORTED,
            expected.getReason());
      }
    }
  }

  /**
   * Tests the checkNoHostPort(URI) method.
   */
  @Test public final void testCheckNoHostPort() {
    // Acceptance cases
    for (String address : new String[] {
        "k2://u@/p?q#f", "//:0", "//:", "///p", ""
    }) {
      try {
        AddressUtilities.checkNoHostPort(URI.create(address));
      } catch (IllegalAddressException ex) {
        fail("Address is acceptable: " + address);
      }
    }
    // Rejection cases
    for (String address : new String[] {
        "k2://h:1", "//h:0", "//h:", "//h"
        // NOTE: a port alone (e.g. "//:80") does not get parsed without a host
    }) {
      try {
        AddressUtilities.checkNoHostPort(URI.create(address));
        fail("Should reject " + address);
      } catch (IllegalAddressException expected) {
        assertEquals(address, expected.getAddress());
        assertEquals(
            IllegalAddressException.Reason.HOST_PORT_UNSUPPORTED,
            expected.getReason());
      }
    }
  }

  /**
   * Tests the checkNoPath(URI) method.
   */
  @Test public final void testCheckNoPath() {
    // Acceptance cases
    for (String address : new String[] {
        "k2://u@h:1?q#f", "//h:1", "?q#f", ""
    }) {
      try {
        AddressUtilities.checkNoPath(URI.create(address));
      } catch (IllegalAddressException ex) {
        fail("Address is acceptable: " + address);
      }
    }
    // Rejection cases
    for (String address : new String[] {
        "k2://h:1/", "///", "/", ".", "..", "~"
    }) {
      try {
        AddressUtilities.checkNoPath(URI.create(address));
        fail("Should reject: " + address);
      } catch (IllegalAddressException expected) {
        assertEquals(address, expected.getAddress());
        assertEquals(
            IllegalAddressException.Reason.PATH_UNSUPPORTED,
            expected.getReason());
      }
    }
  }
  
  /**
   * Tests the checkNoQuery(URI) method.
   */
  @Test public final void testCheckNoQuery() {
    // Acceptance cases
    for (String address : new String[] {
        "k2://u@h:1/p#f", "//u@h:1/p?#f", "?#f", "?", ""
    }) {
      try {
        AddressUtilities.checkNoQuery(URI.create(address));
      } catch (IllegalAddressException ex) {
        throw new AssertionError("Address is acceptable: " + address, ex);
      }
    }
    // Rejection cases
    for (String address : new String[] {
        "k2:/p?q", "//h:1/?q", "?q"
    }) {
      try {
        AddressUtilities.checkNoQuery(URI.create(address));
        fail("Should reject " + address);
      } catch (IllegalAddressException expected) {
        assertEquals(address, expected.getAddress());
        assertEquals(
            IllegalAddressException.Reason.QUERY_UNSUPPORTED,
            expected.getReason());
      }
    }
  }

  /**
   * Tests the checkNoFragment(URI) method.
   */
  @Test public final void testCheckNoFragment() {
    // Acceptance cases
    for (String address : new String[] {
        "k2://u@h:1/p?q", "//u@h:1/p?q#", "?q#", "#", ""
    }) {
      try {
        AddressUtilities.checkNoFragment(URI.create(address));
      } catch (IllegalAddressException ex) {
        throw new AssertionError("Address is acceptable: " + address, ex);
      }
    }
    // Rejection cases
    for (String address : new String[] {
        "k2:/p#f", "//h:1/?#f", "#f"
    }) {
      try {
        AddressUtilities.checkNoFragment(URI.create(address));
        fail("Should reject " + address);
      } catch (IllegalAddressException expected) {
        assertEquals(address, expected.getAddress());
        assertEquals(
            IllegalAddressException.Reason.FRAGMENT_UNSUPPORTED,
            expected.getReason());
      }
    }
  }

  /**
   * Tests the extractHost(URI) method.
   */
  @Test public final void testExtractHost() {
    // Acceptance cases
    checkExtractHost("h", "k2://u@h:1/p?q#f");
    checkExtractHost("1.1.1.1", "//1.1.1.1:0");
    checkExtractHost("255.255.255.255", "//255.255.255.255#f");
    checkExtractHost("[0:0:0:0:0:0:0:0]", "ipv6://[0:0:0:0:0:0:0:0]:1?q");
    
    // Rejection cases    
    for (String address : new String[] {
        "k2:p?q#f", "p?q#f", "h", ""
    }) {
      try {
        AddressUtilities.extractHost(URI.create(address));
        fail("Should reject " + address);
      } catch (IllegalAddressException expected) {
        assertEquals(address, expected.getAddress());
        assertEquals(
            IllegalAddressException.Reason.MISSING_HOST_PORT,
            expected.getReason());
      }
    }
  }
  
  /**
   * Checks that the extractHost method returns the expected value.
   * 
   * @param expected Expected host value.
   * @param address Input address.
   */
  private static void checkExtractHost(String expected, String address) {
    try {
      assertEquals(
          expected, AddressUtilities.extractHost(URI.create(address)));
    } catch (IllegalAddressException ex) {
      throw new AssertionError("Address is acceptable: " + address, ex);
    }    
  }
  
  /**
   * Tests the extractRawPath(URI) method.
   */
  @Test public final void testExtractRawPath() {
    // Acceptance cases
    checkExtractRawPath("/", "k2:///");
    checkExtractRawPath("/./p/../", "file:/./p/../");
    checkExtractRawPath("/%20", "k2://u@h:1/%20?q#f");
    
    // Rejection cases    
    for (String address : new String[] {
        "k2://u@h:1?q#f", "//h:1", "?q#f", ""
    }) {
      try {
        AddressUtilities.extractRawPath(URI.create(address));
        fail("Should reject " + address);
      } catch (IllegalAddressException expected) {
        assertEquals(address, expected.getAddress());
        assertEquals(
            IllegalAddressException.Reason.MISSING_PATH,
            expected.getReason());
      }
    }
  }
  
  /**
   * Checks that the extractRawPath method returns the expected value.
   * 
   * @param expected Expected path value.
   * @param address Input address.
   */
  private static void checkExtractRawPath(String expected, String address) {
    try {
      assertEquals(
          expected, AddressUtilities.extractRawPath(URI.create(address)));
    } catch (IllegalAddressException ex) {
      throw new AssertionError("Address is acceptable: " + address, ex);
    }    
  }
  
  /**
   * Tests the extractRawQuery(URI) method.
   */
  @Test public final void testExtractRawQuery() {
    // Acceptance cases
    checkExtractRawQuery("q", "?q");
    checkExtractRawQuery("q", "k2://u@h:1/p?q#f");
    checkExtractRawQuery("+&%20=x", "?+&%20=x");
    checkExtractRawQuery("%20", "/%3Fp?%20#f");
    
    // Rejection cases
    for (String address : new String[] {
        "k2://u@h:1/p?#f", "//h:1/p", "#f", "?", "%3Fq", ""
    }) {
      try {
        AddressUtilities.extractRawQuery(URI.create(address));
        fail("Should reject " + address);
      } catch (IllegalAddressException expected) {
        assertEquals(address, expected.getAddress());
        assertEquals(
            IllegalAddressException.Reason.MISSING_QUERY,
            expected.getReason());
      }
    }
  }
  
  /**
   * Checks that the extractRawQuery method returns the expected value.
   * 
   * @param expected Expected query value.
   * @param address Input address.
   */
  private static void checkExtractRawQuery(String expected, String address) {
    try {
      assertEquals(
          expected, AddressUtilities.extractRawQuery(URI.create(address)));
    } catch (IllegalAddressException ex) {
      throw new AssertionError("Address is acceptable: " + address, ex);
    }    
  }

  /**
   * Tests the extractFragment(URI) method.
   */
  @Test public final void testExtractFragment() {
    // Acceptance cases
    checkExtractFragment("f", "#f");
    checkExtractFragment("0", "k2://u@h:1/p?q#0");
    checkExtractFragment(" ", "#%20");
    checkExtractFragment("f +", "?%23q#f%20+");
    
    // Rejection cases
    for (String address : new String[] {
        "k2://u@h:1/p?q#", "//h:1/p?q", "#", "%23f", ""
    }) {
      try {
        AddressUtilities.extractFragment(URI.create(address));
        fail("Should reject " + address);
      } catch (IllegalAddressException expected) {
        assertEquals(address, expected.getAddress());
        assertEquals(
            IllegalAddressException.Reason.MISSING_FRAGMENT,
            expected.getReason());
      }
    }
  }
  
  /**
   * Checks that the extractFragment method returns the expected value.
   * 
   * @param expected Expected fragment value.
   * @param address Input address.
   */
  private static void checkExtractFragment(String expected, String address) {
    try {
      assertEquals(
          expected, AddressUtilities.extractFragment(URI.create(address)));
    } catch (IllegalAddressException ex) {
      throw new AssertionError("Address is acceptable: " + address, ex);
    }    
  }
}
