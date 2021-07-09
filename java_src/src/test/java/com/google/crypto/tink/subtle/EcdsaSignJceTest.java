// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.subtle;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.subtle.EllipticCurves.EcdsaEncoding;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for EcdsaSignJce.
 */
@RunWith(JUnit4.class)
public class EcdsaSignJceTest {

  @Before
  public void useConscrypt() throws Exception {
    // If Tink is build in FIPS-only mode, then we register Conscrypt for the tests.
    if (TinkFips.useOnlyFips()) {
      try {
        Conscrypt.checkAvailability();
        Security.addProvider(Conscrypt.newProvider());
      } catch (Throwable cause) {
        throw new IllegalStateException(
            "Cannot test ECDSA sign in FIPS-mode without Conscrypt Provider", cause);
      }
    }
  }

  @Test
  public void testBasic() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    ECParameterSpec ecParams = EllipticCurves.getNistP256Params();
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(ecParams);
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();

    // Sign with EcdsaSign.
    String message = "Hello";
    EcdsaSignJce signer = new EcdsaSignJce(priv, HashType.SHA256, EcdsaEncoding.DER);
    byte[] signature = signer.sign(message.getBytes("UTF-8"));

    // Verify with JCE's Signature.
    Signature verifier = Signature.getInstance("SHA256WithECDSA");
    verifier.initVerify(pub);
    verifier.update(message.getBytes("UTF-8"));
    assertTrue(verifier.verify(signature));
  }

  @Test
  public void testConstructorExceptions() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    ECParameterSpec ecParams = EllipticCurves.getNistP256Params();
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(ecParams);
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> new EcdsaSignJce(priv, HashType.SHA1, EcdsaEncoding.DER));
    TestUtil.assertExceptionContains(e, "Unsupported hash: SHA1");
  }

  @Test
  public void testBitFlipAgainstSignatureInstance() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    ECParameterSpec ecParams = EllipticCurves.getNistP256Params();
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(ecParams);
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();

    // Sign with EcdsaSign.
    String message = "Hello";
    EcdsaSignJce signer = new EcdsaSignJce(priv, HashType.SHA256, EcdsaEncoding.DER);
    byte[] signature = signer.sign(message.getBytes("UTF-8"));

    for (int i = 0; i < signature.length; i++) {
      for (int j = 0; j < 8; j++) {
        signature[i] = (byte) (signature[i] ^ (1 << j));
        // Verify with JCE's Signature.
        Signature verifier = Signature.getInstance("SHA256WithECDSA");
        verifier.initVerify(pub);
        verifier.update(message.getBytes("UTF-8"));
        boolean verified = true;
        try {
          verified = verifier.verify(signature);
        } catch (GeneralSecurityException expected) {
          verified = false;
        }
        assertFalse(verified);
        signature[i] = (byte) (signature[i] ^ (1 << j));
      }
    }
  }

  @Test
  public void testFailIfFipsModuleNotAvailable() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable());

    ECParameterSpec ecParams = EllipticCurves.getNistP256Params();
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(ecParams);
    KeyPair keyPair = keyGen.generateKeyPair();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            new EcdsaSignJce(
                (ECPrivateKey) keyPair.getPrivate(), HashType.SHA256, EcdsaEncoding.DER));
  }
}
