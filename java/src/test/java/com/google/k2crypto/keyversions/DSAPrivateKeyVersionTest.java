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

package com.google.k2crypto.keyversions;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import com.google.k2crypto.exceptions.BuilderException;
import com.google.k2crypto.exceptions.EncryptionException;

import org.junit.Test;

/**
 * Test signing and verification for DSAPrivateKeyVersion class using DSAPublicKeyVersion for
 * verification
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public class DSAPrivateKeyVersionTest {

  /**
   * Method to test digital signing and verification. Can be slow to run due to use of SecureRandom
   *
   * @throws EncryptionException
   * @throws BuilderException
   */
  @Test
  public void testSignVerify() throws EncryptionException, BuilderException {
    // create a DSAPrivateKeyVersion using the builder object
    DSAPrivateKeyVersion keyversion1 = new DSAPrivateKeyVersion.Builder().build();

    // test data to sign
    byte[] data = "Get swole or die trying".getBytes();
    // make the digital signature
    byte[] digitalSignature = keyversion1.signData(data);

    // now verify using the public key
    boolean verified = keyversion1.getPublic().verifySig(data, digitalSignature);
    System.out.println(verified);
    assertTrue(verified);

    // now check that the signature does not verify using a different public key
    DSAPrivateKeyVersion keyversion2 = new DSAPrivateKeyVersion.Builder().build();
    verified = keyversion2.getPublic().verifySig(data, digitalSignature);
    System.out.println(verified);
    assertFalse(verified);
  }



}
