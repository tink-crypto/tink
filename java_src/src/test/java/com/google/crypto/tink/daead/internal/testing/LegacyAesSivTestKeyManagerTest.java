// Copyright 2023 Google LLC
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

package com.google.crypto.tink.daead.internal.testing;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.AesSivKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.AesSiv;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class LegacyAesSivTestKeyManagerTest {
  /** Type url that this manager supports. */
  public static final String TYPE_URL = "type.googleapis.com/custom.AesSivKey";

  @BeforeClass
  public static void setUp() throws Exception {
    LegacyAesSivTestKeyManager.register();
  }

  @Test
  public void getPrimitive_works() throws Exception {
    AesSivKey key =
        AesSivKey.newBuilder()
            .setKeyValue(ByteString.copyFrom(Random.randBytes(64)))
            .setVersion(0)
            .build();
    KeyData keyData =
        KeyData.newBuilder()
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .setTypeUrl(TYPE_URL)
            .setValue(key.toByteString())
            .build();

    DeterministicAead daead = Registry.getPrimitive(keyData, DeterministicAead.class);

    assertThat(daead).isNotNull();
    assertThat(daead).isInstanceOf(AesSiv.class);
  }

  @Test
  public void getPrimitive_encryptDecryptDeterministically_works() throws Exception {
    AesSivKey key =
        AesSivKey.newBuilder()
            .setKeyValue(ByteString.copyFrom(Random.randBytes(64)))
            .setVersion(0)
            .build();
    KeyData keyData =
        KeyData.newBuilder()
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .setTypeUrl(TYPE_URL)
            .setValue(key.toByteString())
            .build();

    DeterministicAead daead = Registry.getPrimitive(keyData, DeterministicAead.class);
    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    byte[] ciphertext = daead.encryptDeterministically(plaintext, associatedData);
    byte[] ciphertext2 = daead.encryptDeterministically(plaintext, associatedData);
    byte[] decrypted = daead.decryptDeterministically(ciphertext, associatedData);
    byte[] decrypted2 = daead.decryptDeterministically(ciphertext2, associatedData);

    assertArrayEquals(ciphertext, ciphertext2);
    assertArrayEquals(plaintext, decrypted);
    assertArrayEquals(plaintext, decrypted2);
  }

  @Test
  public void getPrimitive_wrongKeySize_throws() throws Exception {
    AesSivKey key =
        AesSivKey.newBuilder()
            .setKeyValue(ByteString.copyFrom(Random.randBytes(32)))
            .setVersion(0)
            .build();
    KeyData keyData =
        KeyData.newBuilder()
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .setTypeUrl(TYPE_URL)
            .setValue(key.toByteString())
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> Registry.getPrimitive(keyData, DeterministicAead.class));
  }
}
