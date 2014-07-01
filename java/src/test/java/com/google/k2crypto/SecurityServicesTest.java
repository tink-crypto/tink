/*
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package com.google.k2crypto;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import java.util.HashSet;

/**
 * This class tests getting the algorithms that satisfy given security services in K2.
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public class SecurityServicesTest {

  /**
   * Test getting an algorithm for ONE security service
   */
  @Test
  public void testGetAlgorithmsOneSecurityService() {
    // list of the expected algorithms to be output
    HashSet<Algorithm> expectedAlgorithms = new HashSet<Algorithm>();
    expectedAlgorithms.add(Algorithm.HMAC);
    // get the algorithms from the security services class for data integrity
    HashSet<Algorithm> result = SecurityServices.getAlgorithms(SecService.DATA_INTEGRITY);
    // check they are equal
    assertEquals(expectedAlgorithms, result);

    // now test for authentication
    result = SecurityServices.getAlgorithms(SecService.AUTHENTICATION);
    assertEquals(expectedAlgorithms, result);

    // clear the expected algorithms
    expectedAlgorithms.clear();

    // now test for confidentiality
    expectedAlgorithms.add(Algorithm.AES);
    result = SecurityServices.getAlgorithms(SecService.CONFIDENTIALITY);
    assertEquals(expectedAlgorithms, result);

    // now test for non repudiation
    expectedAlgorithms.clear();
    expectedAlgorithms.add(Algorithm.DSA);
    result = SecurityServices.getAlgorithms(SecService.NON_REPUDIATION);
    assertEquals(expectedAlgorithms, result);
  }

  /**
   * Test getting algorithms for TWO security services
   */
  @Test
  public void testGetAlgorithmsTwoSecurityServices() throws K2Exception {
    // list of the expected algorithms to be output
    HashSet<Algorithm> expectedAlgorithms = new HashSet<Algorithm>();
    expectedAlgorithms.add(Algorithm.HMAC);
    // get the algorithms from the security services class for data integrity
    HashSet<Algorithm> result =
        SecurityServices.getAlgorithms(SecService.DATA_INTEGRITY, SecService.AUTHENTICATION);
    // check they are equal
    assertEquals(expectedAlgorithms, result);

    // clear the expected algorithms
    expectedAlgorithms.clear();
    expectedAlgorithms.add(Algorithm.AES);
    expectedAlgorithms.add(Algorithm.HMAC);

    result = SecurityServices.getAlgorithms(SecService.CONFIDENTIALITY, SecService.DATA_INTEGRITY);
    assertEquals(expectedAlgorithms, result);
    result = SecurityServices.getAlgorithms(SecService.CONFIDENTIALITY, SecService.AUTHENTICATION);
    assertEquals(expectedAlgorithms, result);

    expectedAlgorithms.clear();
    expectedAlgorithms.add(Algorithm.DSA);
    result = SecurityServices.getAlgorithms(SecService.NON_REPUDIATION, SecService.DATA_INTEGRITY);
    assertEquals(expectedAlgorithms, result);
    result = SecurityServices.getAlgorithms(SecService.NON_REPUDIATION, SecService.AUTHENTICATION);
    assertEquals(expectedAlgorithms, result);

    expectedAlgorithms.clear();
    expectedAlgorithms.add(Algorithm.DSA);
    expectedAlgorithms.add(Algorithm.AES);
    result = SecurityServices.getAlgorithms(SecService.NON_REPUDIATION, SecService.CONFIDENTIALITY);
    assertEquals(expectedAlgorithms, result);
  }

  /**
   * Test getting algorithms for THREE security services
   */
  @Test
  public void testGetAlgorithmsThreeSecurityServices() throws K2Exception {
    // list of the expected algorithms to be output
    HashSet<Algorithm> expectedAlgorithms = new HashSet<Algorithm>();
    expectedAlgorithms.add(Algorithm.DSA);

    // get the algorithms from the security services class for data integrity
    HashSet<Algorithm> result = SecurityServices.getAlgorithms(SecService.DATA_INTEGRITY,
        SecService.NON_REPUDIATION, SecService.AUTHENTICATION);
    // check they are equal
    assertEquals(expectedAlgorithms, result);

    expectedAlgorithms.clear();
    expectedAlgorithms.add(Algorithm.HMAC);
    expectedAlgorithms.add(Algorithm.AES);
    result = SecurityServices.getAlgorithms(SecService.DATA_INTEGRITY, SecService.CONFIDENTIALITY,
        SecService.AUTHENTICATION);
    assertEquals(expectedAlgorithms, result);

    expectedAlgorithms.clear();
    expectedAlgorithms.add(Algorithm.DSA);
    expectedAlgorithms.add(Algorithm.AES);
    result = SecurityServices.getAlgorithms(SecService.DATA_INTEGRITY, SecService.CONFIDENTIALITY,
        SecService.NON_REPUDIATION);
    assertEquals(expectedAlgorithms, result);

    expectedAlgorithms.clear();
    expectedAlgorithms.add(Algorithm.DSA);
    expectedAlgorithms.add(Algorithm.AES);
    result = SecurityServices.getAlgorithms(SecService.AUTHENTICATION, SecService.CONFIDENTIALITY,
        SecService.NON_REPUDIATION);
    assertEquals(expectedAlgorithms, result);
  }

  /**
   * Test getting algorithms for FOUR security services
   */
  @Test
  public void testGetAlgorithmsFourSecurityServices() throws K2Exception {
    // list of the expected algorithms to be output
    HashSet<Algorithm> expectedAlgorithms = new HashSet<Algorithm>();
    expectedAlgorithms.add(Algorithm.DSA);
    expectedAlgorithms.add(Algorithm.AES);

    // get the algorithms from the security services class for data integrity
    HashSet<Algorithm> result = SecurityServices.getAlgorithms(SecService.DATA_INTEGRITY,
        SecService.NON_REPUDIATION, SecService.AUTHENTICATION, SecService.CONFIDENTIALITY);
    // check they are equal
    assertEquals(expectedAlgorithms, result);
  }

  /**
   * Testing throwing exception when we provide duplicate data integrity security services
   *
   * @throws K2Exception
   */
  @Test(expected = K2Exception.class)
  public void testDataIntegrityTwoDuplicate() throws K2Exception {
    SecurityServices.getAlgorithms(SecService.DATA_INTEGRITY, SecService.DATA_INTEGRITY);
  }

  /**
   * Testing throwing exception when we provide duplicate authentication security services
   *
   * @throws K2Exception
   */
  @Test(expected = K2Exception.class)
  public void testAuthenticationTwoDuplicate() throws K2Exception {
    SecurityServices.getAlgorithms(SecService.AUTHENTICATION, SecService.AUTHENTICATION);
  }

  /**
   * Testing throwing exception when we provide duplicate non repudiation security services
   *
   * @throws K2Exception
   */
  @Test(expected = K2Exception.class)
  public void testNonRepudiationTwoDuplicate() throws K2Exception {
    SecurityServices.getAlgorithms(SecService.NON_REPUDIATION, SecService.NON_REPUDIATION);
  }

  /**
   * Testing throwing exception when we provide duplicate confidentiality security services
   *
   * @throws K2Exception
   */
  @Test(expected = K2Exception.class)
  public void testConfidentialityTwoDuplicate() throws K2Exception {
    SecurityServices.getAlgorithms(SecService.CONFIDENTIALITY, SecService.CONFIDENTIALITY);
  }

  /**
   * Testing throwing exception when we provide duplicate security services when supplying three
   * security services
   *
   * @throws K2Exception
   */
  @Test(expected = K2Exception.class)
  public void testThreeDuplicateSecurityServices() throws K2Exception {
    SecurityServices.getAlgorithms(SecService.DATA_INTEGRITY, SecService.AUTHENTICATION,
        SecService.DATA_INTEGRITY);
  }

  /**
   * Testing throwing exception when we provide duplicate security services when supplying four
   * security services
   *
   * @throws K2Exception
   */
  @Test(expected = K2Exception.class)
  public void testFourDuplicateSecurityServices() throws K2Exception {
    SecurityServices.getAlgorithms(SecService.DATA_INTEGRITY, SecService.AUTHENTICATION,
        SecService.DATA_INTEGRITY, SecService.CONFIDENTIALITY);
  }
}
