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
 * This class is the API through which people secure their data. You ask for a set of security
 * services that you want and the system secures your data to satisfy these services
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public class SecureData {

  /**
   * takes a list of desired security services and initializes the set of algorithms accordingly
   *
   * @param secServices List of desired security services
   * @throws K2Exception
   */
  public static CompoundKey getKey(SecService... secServices) throws K2Exception {
    /**
     * The algorithms that we will use to secure our data
     */
    HashSet<Algorithm> algorithms = new HashSet<Algorithm>();

    /**
     * The compound key used to perform the cryptographic operations
     */
    CompoundKey key = new CompoundKey();

    // get the algorithms we need to provide the desired security services
    int numArgs = secServices.length;
    if (numArgs == 0) {
      throw new K2Exception("Must provide desired security services");
    } else if (numArgs == 1) {
      algorithms = SecurityServices.getAlgorithms(secServices[0]);
    } else if (numArgs == 2) {
      algorithms = SecurityServices.getAlgorithms(secServices[0], secServices[1]);
    } else if (numArgs == 3) {
      algorithms = SecurityServices.getAlgorithms(secServices[0], secServices[1], secServices[2]);
    } else {
      algorithms = SecurityServices.getAlgorithms(secServices[0], secServices[1], secServices[2],
          secServices[3]);
    }

    System.out.println(algorithms);

    // initialize the key according to which algorithms we require
    if (algorithms.contains(Algorithm.AES)) {
      // encryption key
      key.initSymEncryption();
    }
    if (algorithms.contains(Algorithm.DSA)) {
      // signing key
      key.initSigning();
    }
    if (algorithms.contains(Algorithm.HMAC)) {
      // hmac key
      key.initHmac();
    }

    return key;
  }

}
