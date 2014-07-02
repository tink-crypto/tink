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

import java.util.HashSet;

/**
 * This class represents the list of security services in K2. It provides a mapping from security
 * services to suggested cryptographic algorithms that should be used to provide these services.
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public class SecurityServices { 
  /**
   * function that maps from ONE security services to ONE algorithm
   *
   * @param secService The security service that we want to provide
   * @return The list containing the algorithm that provides that security service
   */
  public static HashSet<Algorithm> getAlgorithms(SecService secService) {
    // create list that we will return of the algorithms
    HashSet<Algorithm> algorithms = new HashSet<Algorithm>();
    // if we want confidentiality use AES
    if (secService == SecService.CONFIDENTIALITY) {
      algorithms.add(Algorithm.AES);
      return algorithms;
    } else if (secService == SecService.DATA_INTEGRITY || secService == SecService.AUTHENTICATION) {
      // integrity, authentication - use HMAC
      algorithms.add(Algorithm.HMAC);
      return algorithms;
    } else {
      // for non-repudiation use DSA
      algorithms.add(Algorithm.DSA);
      return algorithms;
    }
  }

  /**
   * function that maps from TWO security services to ONE or TWO algorithms
   *
   * @param secService1 A security service we want to provide
   * @param secService2 Another security service we want to provide
   * @return An HashSet of algorithms which when used together provide the requested security
   *         properties
   * @throws K2Exception
   */
  public static HashSet<Algorithm> getAlgorithms(SecService secService1,
      SecService secService2) throws K2Exception {
    // check that the security services are different
    if (secService1 == secService2) {
      // throw an exception if they are the same
      throw new K2Exception("When providing multiple security services each one must be different");
    }

    // add security services to list so we can check using contains instead of having to check each
    // one individually
    HashSet<SecService> services = new HashSet<SecService>();
    services.add(secService1);
    services.add(secService2);

    // create list that we will return of the algorithms
    HashSet<Algorithm> algorithms = new HashSet<Algorithm>();

    // if we want integrity and authentication use HMAC
    if (services.contains(SecService.DATA_INTEGRITY)
        && services.contains(SecService.AUTHENTICATION)) {
      // use HMAC
      algorithms.add(Algorithm.HMAC);
      return algorithms;
    } else if (services.contains(SecService.CONFIDENTIALITY)) {
      // if we want confidentiality we have to use AES
      algorithms.add(Algorithm.AES);
      // if we also want data integrity or authentication, add an HMAC
      if (services.contains(SecService.DATA_INTEGRITY)
          || services.contains(SecService.AUTHENTICATION)) {
        // add HMAC
        algorithms.add(Algorithm.HMAC);
        return algorithms;
      } else {
        // otherwise add DSA for non-repudiation
        algorithms.add(Algorithm.DSA);
        return algorithms;
      }
    } else {
      // otherwise just use DSA for data integrity and non repudiation, or authentication and non
      // repudiation
      algorithms.add(Algorithm.DSA);
      return algorithms;
    }
  }

  /**
   * A function that maps from THREE security services to a list of algorithms that together satisfy
   * these
   *
   * @param secService1 A security service we want to provide
   * @param secService2 A second security service we want to provide
   * @param secService3 A third security service we want to provide
   * @return An HashSet of algorithms which when used together provide the requested security
   *         properties
   * @throws K2Exception
   */
  public static HashSet<Algorithm> getAlgorithms(SecService secService1,
      SecService secService2, SecService secService3) throws K2Exception {
    // check that the security services are different
    if (secService1 == secService2 || secService1 == secService3 || secService2 == secService3) {
      // throw an exception if any of them are the same
      throw new K2Exception("When providing multiple security services each one must be different");
    }

    // add security services to list so we can check using contains instead of having to check each
    // one individually
    HashSet<SecService> services = new HashSet<SecService>();
    services.add(secService1);
    services.add(secService2);
    services.add(secService3);

    // create list that we will return of the algorithms
    HashSet<Algorithm> algorithms = new HashSet<Algorithm>();

    // confidentiality, data integrity, authentication - use AES and HMAC
    if (services.contains(SecService.CONFIDENTIALITY)
        && services.contains(SecService.DATA_INTEGRITY)
        && services.contains(SecService.AUTHENTICATION)) {
      // use AES and HMAC
      algorithms.add(Algorithm.AES);
      algorithms.add(Algorithm.HMAC);
      return algorithms;
    } else if (services.contains(SecService.DATA_INTEGRITY)
        && services.contains(SecService.AUTHENTICATION)
        && services.contains(SecService.NON_REPUDIATION)) {
      // data integrity, authentication, non repudiation - use DSA
      algorithms.add(Algorithm.DSA);
      return algorithms;
    } else {
      // use AES and DSA
      algorithms.add(Algorithm.AES);
      algorithms.add(Algorithm.DSA);
      return algorithms;
    }
  }

  /**
   * A function that maps from FOUR security services to a list of algorithms that together satisfy
   * these
   *
   * @param secService1 A security service we want to provide
   * @param secService2 A second security service we want to provide
   * @param secService3 A third security service we want to provide
   * @param secService4 A fourth security service we want to provide
   * @return An HashSet of algorithms which when used together provide the requested security
   *         properties
   * @throws K2Exception
   */
  public static HashSet<Algorithm> getAlgorithms(SecService secService1,
      SecService secService2, SecService secService3, SecService secService4) throws K2Exception {
    // check that the security services are different
    if (secService1 == secService2 || secService1 == secService3 || secService1 == secService4
        || secService2 == secService3 || secService2 == secService4 || secService3 == secService4) {
      // throw an exception if any of them are the same
      throw new K2Exception("When providing multiple security services each one must be different");
    }
    // create list that we will return of the algorithms
    HashSet<Algorithm> algorithms = new HashSet<Algorithm>();
    // all four security properties are satisfied by AES + DSA
    algorithms.add(Algorithm.AES);
    algorithms.add(Algorithm.DSA);
    return algorithms;
  }
}
