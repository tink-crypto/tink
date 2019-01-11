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

import static org.junit.Assert.fail;

import com.google.crypto.tink.Config;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.TestUtil.BytesMutation;
import com.google.crypto.tink.proto.Ed25519PrivateKey;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for Ed25519PublicKeyManager. */
@RunWith(JUnit4.class)
public class Ed25519PublicKeyManagerTest {
  @Before
  public void setUp() throws GeneralSecurityException {
    Config.register(SignatureConfig.TINK_1_0_0);
  }

  @Test
  public void testModifiedSignature() throws Exception {
    Ed25519PrivateKeyManager manager = new Ed25519PrivateKeyManager();
    KeyTemplate template = SignatureKeyTemplates.ED25519;
    MessageLite key = manager.newKey(template.getValue());
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

    for (BytesMutation mutation : TestUtil.generateMutations(message)) {
      try {
        verifier.verify(signature, mutation.value);
        fail(
            String.format(
                "Invalid message, should have thrown exception: sig = %s, msg = %s,"
                    + " description = %s",
                Hex.encode(signature), Hex.encode(mutation.value), mutation.description));
      } catch (GeneralSecurityException expected) {
        // Expected.
      }
    }

    for (BytesMutation mutation : TestUtil.generateMutations(signature)) {
      try {
        verifier.verify(mutation.value, message);
        fail(
            String.format(
                "Invalid signature, should have thrown exception: signature = %s, msg = %s,"
                    + " description = %s",
                Hex.encode(mutation.value), Hex.encode(message), mutation.description));
      } catch (GeneralSecurityException expected) {
        // Expected.
      }
    }
  }
}
