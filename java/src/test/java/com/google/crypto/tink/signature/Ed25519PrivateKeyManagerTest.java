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

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;
import static junit.framework.Assert.fail;

import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.proto.Ed25519PrivateKey;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.subtle.Ed25519Sign;
import com.google.crypto.tink.subtle.Ed25519Verify;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for Ed25519PrivateKeyManager.
 */
@RunWith(JUnit4.class)
public class Ed25519PrivateKeyManagerTest {
  @Before
  public void setUp() throws GeneralSecurityException {
    PublicKeySignConfig.registerStandardKeyTypes();
    PublicKeyVerifyConfig.registerStandardKeyTypes();
  }

  @Test
  public void testBasic() throws Exception {
    Ed25519PrivateKeyManager manager = new Ed25519PrivateKeyManager();
    KeyTemplate template = SignatureKeyTemplates.ED25519;
    MessageLite key = manager.newKey(template);
    assertTrue(key instanceof Ed25519PrivateKey);

    Ed25519PrivateKey keyProto = (Ed25519PrivateKey) key;
    assertEquals(32, keyProto.getKeyValue().size());

    PublicKeySign signer = manager.getPrimitive(key);
    assertTrue(signer instanceof Ed25519Sign);
    byte[] message = Random.randBytes(20);
    byte[] signature = signer.sign(message);
    assertEquals(64, signature.length);

    Ed25519PublicKeyManager publicKeyManager = new Ed25519PublicKeyManager();
    PublicKeyVerify verifier = publicKeyManager.getPrimitive(keyProto.getPublicKey());
    assertTrue(verifier instanceof Ed25519Verify);
    try {
      verifier.verify(signature, message);
    } catch (GeneralSecurityException e) {
      fail("Do not expect GeneralSecurityException: " + e);
    }
  }
}
