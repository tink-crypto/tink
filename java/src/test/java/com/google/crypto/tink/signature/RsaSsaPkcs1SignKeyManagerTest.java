// Copyright 2018 Google Inc.
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

package com.google.crypto.tink.signature;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.RsaSsaPkcs1KeyFormat;
import com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for RsaSsaPkcs1SignKeyManager. */
@RunWith(JUnit4.class)
public class RsaSsaPkcs1SignKeyManagerTest {
  @Before
  public void setUp() throws Exception {
    SignatureConfig.register();
  }

  final byte[] msg = Random.randBytes(20);

  private void checkKey(RsaSsaPkcs1PrivateKey privateKey) throws Exception {
    BigInteger p = new BigInteger(1, privateKey.getP().toByteArray());
    BigInteger q = new BigInteger(1, privateKey.getQ().toByteArray());
    BigInteger n = new BigInteger(1, privateKey.getPublicKey().getN().toByteArray());
    BigInteger d = new BigInteger(1, privateKey.getD().toByteArray());
    BigInteger dp = new BigInteger(1, privateKey.getDp().toByteArray());
    BigInteger dq = new BigInteger(1, privateKey.getDq().toByteArray());
    BigInteger crt = new BigInteger(1, privateKey.getCrt().toByteArray());
    assertEquals(n, p.multiply(q));
    assertEquals(dp, d.mod(p.subtract(BigInteger.ONE)));
    assertEquals(dq, d.mod(q.subtract(BigInteger.ONE)));
    assertEquals(crt, q.modInverse(p));
  }

  private void testNewKeyWithVerifier(KeyTemplate keyTemplate) throws Exception {
    // Call newKey multiple times and make sure that it generates different keys.
    int numTests = 3;
    RsaSsaPkcs1PrivateKey[] privKeys = new RsaSsaPkcs1PrivateKey[numTests];
    RsaSsaPkcs1SignKeyManager signManager = new RsaSsaPkcs1SignKeyManager();
    Set<String> keys = new TreeSet<String>();

    privKeys[0] =
        (RsaSsaPkcs1PrivateKey)
            signManager.newKey(RsaSsaPkcs1KeyFormat.parseFrom(keyTemplate.getValue()));
    keys.add(TestUtil.hexEncode(privKeys[0].toByteArray()));

    privKeys[1] = (RsaSsaPkcs1PrivateKey) signManager.newKey(keyTemplate.getValue());
    keys.add(TestUtil.hexEncode(privKeys[1].toByteArray()));

    privKeys[2] =
        RsaSsaPkcs1PrivateKey.parseFrom(signManager.newKeyData(keyTemplate.getValue()).getValue());
    keys.add(TestUtil.hexEncode(privKeys[2].toByteArray()));
    assertEquals(numTests, keys.size());

    // Check key.
    for (int i = 0; i < numTests; i++) {
      checkKey(privKeys[i]);
    }

    // Test whether signer works correctly with the corresponding verifier.
    RsaSsaPkcs1VerifyKeyManager verifyManager = new RsaSsaPkcs1VerifyKeyManager();
    for (int j = 0; j < numTests; j++) {
      PublicKeySign signer = signManager.getPrimitive(privKeys[j]);
      byte[] signature = signer.sign(msg);
      for (int k = 0; k < numTests; k++) {
        PublicKeyVerify verifier = verifyManager.getPrimitive(privKeys[k].getPublicKey());
        if (j == k) { // The same key
          try {
            verifier.verify(signature, msg);
          } catch (GeneralSecurityException ex) {
            throw new AssertionError("Valid signature, should not throw exception", ex);
          }
        } else { // Different keys
          try {
            verifier.verify(signature, msg);
            fail("Invalid signature, should have thrown exception");
          } catch (GeneralSecurityException expected) {
            // Expected
          }
        }
      }
    }
  }

  @Test
  public void testNewKeyWithVerifier() throws Exception {
    if (TestUtil.isTsan()) {
      // This test times out when running under thread sanitizer, so we just skip.
      return;
    }
    testNewKeyWithVerifier(SignatureKeyTemplates.RSA_SSA_PKCS1_3072_SHA256_F4);
    testNewKeyWithVerifier(SignatureKeyTemplates.RSA_SSA_PKCS1_4096_SHA512_F4);
  }

  @Test
  public void testNewKeyWithCorruptedFormat() {
    ByteString serialized = ByteString.copyFrom(new byte[128]);
    KeyTemplate keyTemplate =
        KeyTemplate.newBuilder()
            .setTypeUrl(RsaSsaPkcs1SignKeyManager.TYPE_URL)
            .setValue(serialized)
            .build();
    RsaSsaPkcs1SignKeyManager keyManager = new RsaSsaPkcs1SignKeyManager();
    try {
      keyManager.newKey(serialized);
      fail("Corrupted format, should have thrown exception");
    } catch (GeneralSecurityException expected) {
      // Expected
    }
    try {
      keyManager.newKeyData(keyTemplate.getValue());
      fail("Corrupted format, should have thrown exception");
    } catch (GeneralSecurityException expected) {
      // Expected
    }
  }

  /** Tests that a public key is extracted properly from a private key. */
  @Test
  public void testGetPublicKeyData() throws Exception {
    if (TestUtil.isTsan()) {
      // This test takes over a minute in successful tsan runs and sometimes times out.
      return;
    }
    KeysetHandle privateHandle =
        KeysetHandle.generateNew(SignatureKeyTemplates.RSA_SSA_PKCS1_3072_SHA256_F4);
    KeyData privateKeyData = TestUtil.getKeyset(privateHandle).getKey(0).getKeyData();
    RsaSsaPkcs1SignKeyManager privateManager = new RsaSsaPkcs1SignKeyManager();
    KeyData publicKeyData = privateManager.getPublicKeyData(privateKeyData.getValue());
    assertEquals(RsaSsaPkcs1VerifyKeyManager.TYPE_URL, publicKeyData.getTypeUrl());
    assertEquals(KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC, publicKeyData.getKeyMaterialType());
    RsaSsaPkcs1PrivateKey privateKey = RsaSsaPkcs1PrivateKey.parseFrom(privateKeyData.getValue());
    assertArrayEquals(
        privateKey.getPublicKey().toByteArray(), publicKeyData.getValue().toByteArray());
    RsaSsaPkcs1VerifyKeyManager publicManager = new RsaSsaPkcs1VerifyKeyManager();
    PublicKeySign signer = privateManager.getPrimitive(privateKeyData.getValue());
    PublicKeyVerify verifier = publicManager.getPrimitive(publicKeyData.getValue());
    byte[] message = Random.randBytes(20);
    try {
      verifier.verify(signer.sign(message), message);
    } catch (GeneralSecurityException e) {
      fail("Should not fail: " + e);
    }
  }
}
