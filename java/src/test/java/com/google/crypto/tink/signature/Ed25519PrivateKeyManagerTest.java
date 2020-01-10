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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.fail;

import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.proto.Ed25519KeyFormat;
import com.google.crypto.tink.proto.Ed25519PrivateKey;
import com.google.crypto.tink.proto.Ed25519PublicKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Ed25519Verify;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for Ed25519PrivateKeyManager. */
@RunWith(JUnit4.class)
public class Ed25519PrivateKeyManagerTest {
  private final Ed25519PrivateKeyManager manager = new Ed25519PrivateKeyManager();
  private final KeyTypeManager.KeyFactory<Ed25519KeyFormat, Ed25519PrivateKey> factory =
      manager.keyFactory();

  @Test
  public void basics() throws Exception {
    assertThat(manager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.Ed25519PrivateKey");
    assertThat(manager.getVersion()).isEqualTo(0);
    assertThat(manager.keyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PRIVATE);
  }

  @Test
  public void validateKeyFormat_empty() throws Exception {
    factory.validateKeyFormat(Ed25519KeyFormat.getDefaultInstance());
  }

  @Test
  public void createKey_checkValues() throws Exception {
    Ed25519PrivateKey privateKey = factory.createKey(Ed25519KeyFormat.getDefaultInstance());
    assertThat(privateKey.getVersion()).isEqualTo(0);
    assertThat(privateKey.getPublicKey().getVersion()).isEqualTo(privateKey.getVersion());
    assertThat(privateKey.getKeyValue()).hasSize(32);
    assertThat(privateKey.getPublicKey().getKeyValue()).hasSize(32);
  }

  @Test
  public void validateKey_empty_throws() throws Exception {
    try {
      manager.validateKey(Ed25519PrivateKey.getDefaultInstance());
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  // Tests that generated keys are different.
  @Test
  public void createKey_differentValues() throws Exception {
    Ed25519KeyFormat format = Ed25519KeyFormat.getDefaultInstance();
    Set<String> keys = new TreeSet<>();
    int numTests = 100;
    for (int i = 0; i < numTests; i++) {
      keys.add(TestUtil.hexEncode(factory.createKey(format).getKeyValue().toByteArray()));
    }
    assertThat(keys).hasSize(numTests);
  }

  @Test
  public void createKeyThenValidate() throws Exception {
    manager.validateKey(factory.createKey(Ed25519KeyFormat.getDefaultInstance()));
  }

  @Test
  public void validateKey_wrongVersion() throws Exception {
    Ed25519PrivateKey validKey = factory.createKey(Ed25519KeyFormat.getDefaultInstance());
    Ed25519PrivateKey invalidKey = Ed25519PrivateKey.newBuilder(validKey).setVersion(1).build();
    try {
      manager.validateKey(invalidKey);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void validateKey_wrongLength64_throws() throws Exception {
    Ed25519PrivateKey validKey = factory.createKey(Ed25519KeyFormat.getDefaultInstance());
    Ed25519PrivateKey invalidKey =
        Ed25519PrivateKey.newBuilder(validKey)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(64)))
            .build();
    try {
      manager.validateKey(invalidKey);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void validateKey_wrongLengthPublicKey64_throws() throws Exception {
    Ed25519PrivateKey validKey = factory.createKey(Ed25519KeyFormat.getDefaultInstance());
    Ed25519PrivateKey invalidKey =
        Ed25519PrivateKey.newBuilder(validKey)
            .setPublicKey(
                Ed25519PublicKey.newBuilder(validKey.getPublicKey())
                    .setKeyValue(ByteString.copyFrom(Random.randBytes(64))))
            .build();
    try {
      manager.validateKey(invalidKey);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  /** Tests that a public key is extracted properly from a private key. */
  @Test
  public void getPublicKey_checkValues() throws Exception {
    Ed25519PrivateKey privateKey = factory.createKey(Ed25519KeyFormat.getDefaultInstance());
    Ed25519PublicKey publicKey = manager.getPublicKey(privateKey);
    assertThat(publicKey).isEqualTo(privateKey.getPublicKey());
  }

  @Test
  public void createPrimitive() throws Exception {
    Ed25519PrivateKey privateKey = factory.createKey(Ed25519KeyFormat.getDefaultInstance());
    PublicKeySign signer = manager.getPrimitive(privateKey, PublicKeySign.class);

    PublicKeyVerify verifier =
        new Ed25519Verify(privateKey.getPublicKey().getKeyValue().toByteArray());
    byte[] message = Random.randBytes(135);
    verifier.verify(signer.sign(message), message);
  }
}
