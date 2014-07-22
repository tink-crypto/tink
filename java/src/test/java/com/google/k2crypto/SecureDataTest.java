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

/**
 * Test the overall securing data process.
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public class SecureDataTest {

  /**
   * Test showing how the API is used
   */
  @Test
  public void testExampleUsage() throws K2Exception {
    // example input string
    String testInput = "Google does not support K2";

    // specify the security services you want the key to support
    CompoundKey key = SecureData.getKey(SecService.AUTHENTICATION, SecService.DATA_INTEGRITY);

    // now get your data secured with those security services
    SecureDataBlob secureDataBlob = key.getSecureData(testInput.getBytes());

    // now you can verify the security properties and get the raw data back out
    String outputData = (new String(key.checkAndGetData(secureDataBlob)));

    // Check the output data is the same as the original input data
    assertEquals(testInput, outputData);

    // Print out the input data
    System.out.println("Input data: " + testInput);
    // Print out the output data
    System.out.println("Output data: " + outputData);

  }

  /**
   * Request a key for all possible security services. Then use the key to secure the data. Then
   * verify and check the secured data. This method should NOT throw any exceptions. If it throws
   * exceptions it means the test has failed.
   *
   * @throws K2Exception If the test fails
   */
  @Test
  public void testGetCompoundKeySecureAndCheckData() throws K2Exception {
    // test input string
    String testInput = "Google does not support K2";

    // test with ONE security services
    for (SecService secService : SecService.values()) {
      System.out.print(secService + " ");
      // get the key from the security services
      CompoundKey key = SecureData.getKey(secService);
      // use the key to get the secure data blob
      SecureDataBlob secureDataBlob1 = key.getSecureData(testInput.getBytes());
      // check the output data matches the input data
      assertEquals(new String(key.checkAndGetData(secureDataBlob1)), testInput);
    }

    // test with TWO security services
    for (SecService secService1 : SecService.values()) {
      for (SecService secService2 : SecService.values()) {
        if (!secService1.equals(secService2)) {
          System.out.print(secService1 + " " + secService2 + " ");
          // get the key from the security services
          CompoundKey key = SecureData.getKey(secService1, secService2);
          // use the key to get the secure data blob
          SecureDataBlob secureDataBlob1 = key.getSecureData(testInput.getBytes());
          // check the output data matches the input data
          assertEquals(new String(key.checkAndGetData(secureDataBlob1)), testInput);
        }
      }
    }

    // test with THREE security services
    for (SecService secService : SecService.values()) {
      // array to hold 3 security services
      SecService[] services = new SecService[3];
      int i = 0;
      // add all but one security services to the array
      for (SecService sec2 : SecService.values()) {
        // don't add one security service as we are testing THREE security services, not four
        if (!sec2.equals(secService)) {
          services[i] = sec2;
          i++;
        }
      }
      // print out the security services that we are testing
      for (SecService secPrint : services) {
        System.out.print(secPrint + " ");
      }

      // now use the array of security services to get the key
      CompoundKey key = SecureData.getKey(services);
      // use the key to get the secure data blob
      SecureDataBlob secureDataBlob1 = key.getSecureData(testInput.getBytes());
      // check the output data matches the input data
      assertEquals(new String(key.checkAndGetData(secureDataBlob1)), testInput);
    }

    // test with all FOUR security services
    // print out the security services we are testing
    System.out.print(SecService.DATA_INTEGRITY + " " + SecService.CONFIDENTIALITY + " "
        + SecService.AUTHENTICATION + " " + SecService.NON_REPUDIATION + " ");
    CompoundKey key = SecureData.getKey(SecService.values());
    // use the key to get the secure data blob
    SecureDataBlob secureDataBlob1 = key.getSecureData(testInput.getBytes());
    // check the output data matches the input data
    assertEquals(new String(key.checkAndGetData(secureDataBlob1)), testInput);
  }
}
