// Copyright 2020 Google LLC
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
package com.google.crypto.tink.jwt;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for EcdsaVerifyKeyManager. */
@RunWith(JUnit4.class)
public final class JwtEcdsaVerifyKeyManagerTest {
  @BeforeClass
  public static void setUp() throws Exception {
    JwtSignatureConfig.register();
  }

  @Test
  public void testKeyManagersRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getUntypedKeyManager("type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey"))
        .isNotNull();
  }

  @Test
  public void serializeAndDeserializeKeysets() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES256_RAW");
    KeysetHandle handle = KeysetHandle.generateNew(template).getPublicKeysetHandle();

    byte[] serializedKeyset = TinkProtoKeysetFormat.serializeKeysetWithoutSecret(handle);
    KeysetHandle parsed = TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedKeyset);
    assertTrue(parsed.equalsKeyset(handle));
  }
}
