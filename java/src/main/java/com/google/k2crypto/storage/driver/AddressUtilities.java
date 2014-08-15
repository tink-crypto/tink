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

import com.google.k2crypto.storage.IllegalAddressException;

import java.net.URI;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility methods for checking and manipulating storage URI addresses.
 * 
 * <p>The {@link #encodeConvenience(String)} and
 * {@link #decodeUnreserved(String)} utility methods are required because
 * {@link java.net.URLEncoder} and {@link java.net.URLDecoder} do not provide
 * the desired functionality. Details are provided in the documentation of the
 * individual methods. It boils down to {@link java.net.URLEncoder} and
 * {@link java.net.URLDecoder} being designed to encode and decode ALL
 * percent-encoded characters and ONLY within the query portion of a URL. They
 * are NOT designed for operating on an entire URI, which is what we want to do. 
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
public class AddressUtilities {

  // Prevent instantiation
  private AddressUtilities() {}
  
  // Regex matching percent ('%') characters in the address string that are NOT
  // of the format %[HEX][HEX] and spaces (' ').
  private static final Pattern CONVENIENCE_ENCODABLE =
      Pattern.compile("\\%(?![0-9a-fA-F][0-9a-fA-F])|\\ ");

  // Buffer space for encoding expansion
  private static final int ENCODE_ALLOWANCE = 16;
  
  // Table converting decimal to hex
  private static final char[] HEX_TABLE = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'A', 'B', 'C', 'D', 'E', 'F'
  };
  
  /**
   * Performs safe URI-escaping of the '%' and ' ' characters in the string
   * for convenience sake. This is NOT a complete percent-encoding procedure.
   * The idea is to escape these characters (and only these characters) across
   * the entire URI string so that addresses containing them can remain in a
   * readable form in user code.
   *  
   * <p>The Java-included {@link java.net.URLEncoder} class has similar
   * functionality, but its encoding is designed specifically for the query
   * portion of a URL, and does not work universally across an entire URI.
   * For example, it will encode {@code "/my keys/bank"} as
   * {@code "%2Fmy+keys%2Fbank"}, whereas this method will encode it as
   * {@code "/my%20keys/bank"}. The escaped backslashes and conversion of
   * spaces to {@code '+'} will effectively change the meaning of the address,
   * and this is undesirable behavior. 
   * 
   * @param str String to encode.
   * 
   * @return the string with stray percents and spaces percent-encoded.
   */
  public static String encodeConvenience(String str) {
    Matcher m = CONVENIENCE_ENCODABLE.matcher(str);
    boolean found = m.find();
    if (found) {
      final char[] hexTable = HEX_TABLE;
      StringBuilder sb = new StringBuilder(str.length() + ENCODE_ALLOWANCE);
      int findStart = 0;
      do {
        final int pos = m.start();
        sb.append(str, findStart, pos);
        
        // Percent-encode the encodable character
        final char c = str.charAt(pos);
        sb.append('%').append(hexTable[c >>> 4]).append(hexTable[c & 7]);
        
        findStart = m.end();
        found = m.find();
      } while (found);
      
      sb.append(str, findStart, str.length());
      return sb.toString();
    }
    return str;
  }

  // Regex matching percent-encoded URI-unreserved characters
  // (i.e. letters, digits, '-', '.', '_' and '~')
  private static final Pattern ENCODED_UNRESERVED = Pattern.compile(
      "\\%(?:4[1-9A-F]|5[0-9A]|6[1-9A-F]|7[0-9A]|3[0-9]|2D|2E|5F|7E)",
      Pattern.CASE_INSENSITIVE);
  
  /**
   * Decodes any percent-encoded URI-unreserved characters in the URI address.
   * 
   * <p>As mentioned in <a href="http://tools.ietf.org/html/rfc3986#section-2.3"
   * target="_blank">RFC 3986, Section 2.3</a>, any unreserved characters in a
   * URI should be decoded before the URI can be safely compared or normalized.
   * Unfortunately, Java's URI implementation does not do this for us. 
   *
   * @param address URI to decode.
   * 
   * @return a new URI with all unreserved characters decoded, or the same
   *    URI if there are no unreserved characters to decode.
   * 
   * @see #decodeUnreserved(String)
   */
  public static URI decodeUnreserved(URI address) {
    String addressStr = address.toString();
    String decoded = decodeUnreserved(addressStr);
    return decoded == addressStr ? address : URI.create(decoded);
  }
  
  /**
   * Decodes any percent-encoded URI-unreserved characters in the string.
   * 
   * <p>The Java-included {@link java.net.URLDecoder} class has similar
   * functionality, except it decodes ALL percent-encoded characters; it is
   * designed primarily for decoding individual key/value strings in the query
   * portion of a URL after they have been extracted. For example, it will
   * decode {@code "/my+keys%3F/%62%61%6E%6B"} as {@code "/my keys?/bank"},
   * which will result in an invalid URI because {@code "/bank"} would be
   * interpreted as a query. The {@code '+'} symbol should also only be
   * interpreted as a space in the query portion, and not in any other part of
   * a URI. This method will decode the string as {@code "/my+keys%3F/bank"},
   * preserving the meaning of the address. 
   * 
   * @param str String to decode.
   * 
   * @return the string with all unreserved characters decoded.
   */
  public static String decodeUnreserved(String str) {
    Matcher m = ENCODED_UNRESERVED.matcher(str);
    boolean found = m.find();
    if (found) {
      StringBuilder sb = new StringBuilder(str.length());
      int findStart = 0;
      do {
        final int pos = m.start();
        sb.append(str, findStart, pos);
        
        // Assume that first hex is always a digit (restricted to the regex)
        int decoded = ((str.charAt(pos + 1) - '0') << 4);
        // Complete decoding by checking second hex
        final char hex = str.charAt(pos + 2);
        decoded += hex - (hex <= '9' ? '0' : (hex <= 'Z' ? 'A' : 'a') - 10);
        sb.append((char)decoded);
        
        findStart = m.end();
        found = m.find();
      } while (found);
      
      sb.append(str, findStart, str.length());
      return sb.toString();
    }
    return str;
  }

  /**
   * Checks that the address has no authority component.
   * 
   * @param address Address to check.
   * @throws IllegalAddressException if the authority component exists.
   */
  public static void checkNoAuthority(URI address)
      throws IllegalAddressException {
    if (address.getAuthority() != null) {
      throw new IllegalAddressException(
          address, IllegalAddressException.Reason.AUTHORITY_UNSUPPORTED, null);
    }
  }
  
  /**
   * Checks that the address has no user component.
   * 
   * @param address Address to check.
   * @throws IllegalAddressException if the user component exists.
   */
  public static void checkNoUser(URI address)
      throws IllegalAddressException {
    String user = address.getUserInfo(); 
    if (user != null && user.length() > 0) {
      throw new IllegalAddressException(
          address, IllegalAddressException.Reason.USER_UNSUPPORTED, null);
    }
  }
  
  /**
   * Checks that the address has no host/port component.
   * 
   * @param address Address to check.
   * @throws IllegalAddressException if the host or port component exists.
   */
  public static void checkNoHostPort(URI address)
      throws IllegalAddressException {
    if (address.getHost() != null || address.getPort() >= 0) {
      throw new IllegalAddressException(
          address, IllegalAddressException.Reason.HOST_PORT_UNSUPPORTED, null);
    }
  }
  
  /**
   * Checks that the address has no path component.
   * 
   * @param address Address to check.
   * @throws IllegalAddressException if the path component exists.
   */
  public static void checkNoPath(URI address)
      throws IllegalAddressException {
    String path = address.getPath();
    if (path != null && path.length() > 0) {
      throw new IllegalAddressException(
          address, IllegalAddressException.Reason.PATH_UNSUPPORTED, null);
    }
  }

  /**
   * Checks that the address has no query component.
   * 
   * @param address Address to check.
   * @throws IllegalAddressException if the query component exists.
   */
  public static void checkNoQuery(URI address)
      throws IllegalAddressException {
    String query = address.getQuery(); 
    if (query != null && query.length() > 0) {
      throw new IllegalAddressException(
          address, IllegalAddressException.Reason.QUERY_UNSUPPORTED, null);
    }
  }

  /**
   * Checks that the address has no fragment component.
   * 
   * @param address Address to check.
   * @throws IllegalAddressException if the fragment component exists.
   */
  public static void checkNoFragment(URI address)
      throws IllegalAddressException {
    String fragment = address.getFragment();
    if (fragment != null && fragment.length() > 0) {
      throw new IllegalAddressException(
          address, IllegalAddressException.Reason.FRAGMENT_UNSUPPORTED, null);
    }
  }

  /**
   * Obtains the host from the URI address.
   * 
   * @param address Address to obtain the host from.
   * @throws IllegalAddressException if the address is missing a host.
   */
  public static String extractHost(URI address)
      throws IllegalAddressException {
    String host = address.getHost();
    if (host == null || host.length() == 0) {
      throw new IllegalAddressException(
          address, IllegalAddressException.Reason.MISSING_HOST_PORT, null);
    }
    return host;
  }
  
  /**
   * Obtains the raw path from the URI address.
   * 
   * @param address Address to obtain the path from.
   * @throws IllegalAddressException if the address is missing a path.
   */
  public static String extractRawPath(URI address)
      throws IllegalAddressException {
    String path = address.getRawPath();
    if (path == null || path.length() == 0) {
      throw new IllegalAddressException(
          address, IllegalAddressException.Reason.MISSING_PATH, null);
    }
    return path;
  }
  
  /**
   * Obtains the raw query from the URI address.
   * 
   * @param address Address to obtain the query from.
   * @throws IllegalAddressException if the address is missing a query.
   */
  public static String extractRawQuery(URI address)
      throws IllegalAddressException {
    String query = address.getRawQuery();
    if (query == null || query.length() == 0) {
      throw new IllegalAddressException(
          address, IllegalAddressException.Reason.MISSING_QUERY, null);
    }
    return query;
  }
  
  /**
   * Obtains the fragment from the URI address.
   * 
   * @param address Address to obtain the fragment from.
   * @throws IllegalAddressException if the address is missing a fragment.
   */
  public static String extractFragment(URI address)
      throws IllegalAddressException {
    String frag = address.getFragment();
    if (frag == null || frag.length() == 0) {
      throw new IllegalAddressException(
          address, IllegalAddressException.Reason.MISSING_FRAGMENT, null);
    }
    return frag;
  }
}
