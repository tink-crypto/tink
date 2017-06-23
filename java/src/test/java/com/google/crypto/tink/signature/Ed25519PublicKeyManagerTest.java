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

package com.google.crypto.tink.signature;

import static com.google.crypto.tink.TestUtil.assertExceptionContains;
import static junit.framework.Assert.fail;

import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.proto.Ed25519PrivateKey;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for Ed25519PublicKeyManager.
 */
@RunWith(JUnit4.class)
public class Ed25519PublicKeyManagerTest {
  @Before
  public void setUp() throws GeneralSecurityException {
    PublicKeySignConfig.registerStandardKeyTypes();
    PublicKeyVerifyConfig.registerStandardKeyTypes();
  }

  @Test
  public void testModifiedSignature() throws Exception {
    Ed25519PrivateKeyManager manager = new Ed25519PrivateKeyManager();
    KeyTemplate template = SignatureKeyTemplates.ED25519;
    MessageLite key = manager.newKey(template);
    Ed25519PrivateKey keyProto = (Ed25519PrivateKey) key;

    PublicKeySign signer = manager.getPrimitive(key);
    byte[] message = Random.randBytes(20);
    byte[] signature = signer.sign(message);
    Ed25519PublicKeyManager publicKeyManager = new Ed25519PublicKeyManager();
    PublicKeyVerify verifier = publicKeyManager.getPrimitive(keyProto.getPublicKey());
    try {
      verifier.verify(signature, message);
    } catch (GeneralSecurityException e) {
      fail("Did not expect GeneralSecurityException: " + e);
    }

    // Flip bits in message.
    for (int i = 0; i < message.length; i++) {
      byte[] copy = Arrays.copyOf(message, message.length);
      copy[i] = (byte) (copy[i] ^ 0xff);
      try {
        verifier.verify(signature, copy);
        fail("Expected GeneralSecurityException");
      } catch (GeneralSecurityException e) {
        assertExceptionContains(e, "Signature check failed.");
      }
    }

    // Flip bits in signature.
    // Flip the last byte.
    byte[] copySig = Arrays.copyOf(signature, signature.length);
    copySig[copySig.length - 1] = (byte) (copySig[copySig.length - 1] ^ 0xff);
    try {
      verifier.verify(copySig, message);
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertExceptionContains(e, "Given signature's 3 most significant bits must be 0.");
    }
    // Flip other bytes.
    for (int i = 0; i < signature.length - 1; i++) {
      byte[] copy = Arrays.copyOf(signature, signature.length);
      copy[i] = (byte) (copy[i] ^ 0xff);
      try {
        verifier.verify(copy, message);
        fail("Expected GeneralSecurityException");
      } catch (GeneralSecurityException e) {
        assertExceptionContains(e, "Signature check failed.");
      }
    }
  }
}
