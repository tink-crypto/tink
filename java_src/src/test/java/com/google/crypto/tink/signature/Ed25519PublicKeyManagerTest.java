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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.proto.Ed25519KeyFormat;
import com.google.crypto.tink.proto.Ed25519PrivateKey;
import com.google.crypto.tink.proto.Ed25519PublicKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for Ed25519PublicKeyManager. */
@RunWith(JUnit4.class)
public class Ed25519PublicKeyManagerTest {
  private final Ed25519PrivateKeyManager signManager = new Ed25519PrivateKeyManager();
  private final KeyTypeManager.KeyFactory<Ed25519KeyFormat, Ed25519PrivateKey> factory =
      signManager.keyFactory();

  private final Ed25519PublicKeyManager verifyManager = new Ed25519PublicKeyManager();

  @Test
  public void basics() throws Exception {
    assertThat(verifyManager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.Ed25519PublicKey");
    assertThat(verifyManager.getVersion()).isEqualTo(0);
    assertThat(verifyManager.keyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
  }

  @Test
  public void validateKey_empty_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> verifyManager.validateKey(Ed25519PublicKey.getDefaultInstance()));
  }

  private Ed25519PrivateKey createPrivateKey() throws GeneralSecurityException {
    return factory.createKey(Ed25519KeyFormat.getDefaultInstance());
  }

  @Test
  public void validateKey() throws Exception {
    Ed25519PublicKey publicKey = signManager.getPublicKey(createPrivateKey());
    verifyManager.validateKey(publicKey);
  }

  @Test
  public void validateKey_wrongVersion() throws Exception {
    Ed25519PublicKey publicKey = signManager.getPublicKey(createPrivateKey());
    Ed25519PublicKey invalidKey = Ed25519PublicKey.newBuilder(publicKey).setVersion(1).build();
    assertThrows(GeneralSecurityException.class, () -> verifyManager.validateKey(invalidKey));
  }

  @Test
  public void validateKey_wrongLength31_throws() throws Exception {
    Ed25519PublicKey publicKey = signManager.getPublicKey(createPrivateKey());
    Ed25519PublicKey invalidKey = Ed25519PublicKey.newBuilder(publicKey)
              .setKeyValue(ByteString.copyFrom(Random.randBytes(31)))
              .build();
    assertThrows(GeneralSecurityException.class, () -> verifyManager.validateKey(invalidKey));
  }

  @Test
  public void validateKey_wrongLength64_throws() throws Exception {
    Ed25519PublicKey publicKey = signManager.getPublicKey(createPrivateKey());
    Ed25519PublicKey invalidKey = Ed25519PublicKey.newBuilder(publicKey)
              .setKeyValue(ByteString.copyFrom(Random.randBytes(64)))
              .build();
    assertThrows(GeneralSecurityException.class, () -> verifyManager.validateKey(invalidKey));
  }

  @Test
  public void createPrimitive() throws Exception {
    Ed25519PrivateKey privateKey = createPrivateKey();
    Ed25519PublicKey publicKey = signManager.getPublicKey(privateKey);

    PublicKeySign signer = signManager.getPrimitive(privateKey, PublicKeySign.class);
    PublicKeyVerify verifier = verifyManager.getPrimitive(publicKey, PublicKeyVerify.class);

    byte[] message = Random.randBytes(135);
    verifier.verify(signer.sign(message), message);
  }

  @Test
  public void createPrimitive_anotherKey_throws() throws Exception {
    Ed25519PrivateKey privateKey = createPrivateKey();
    // Create a different key.
    Ed25519PublicKey publicKey = signManager.getPublicKey(createPrivateKey());

    PublicKeySign signer = signManager.getPrimitive(privateKey, PublicKeySign.class);
    PublicKeyVerify verifier = verifyManager.getPrimitive(publicKey, PublicKeyVerify.class);

    byte[] message = Random.randBytes(135);
    byte[] signature = signer.sign(message);
    assertThrows(GeneralSecurityException.class, () -> verifier.verify(signature, message));
  }
}
