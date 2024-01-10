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

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for Ed25519PublicKeyManager. */
@RunWith(JUnit4.class)
public class Ed25519PublicKeyManagerTest {
  @Before
  public void register() throws Exception {
    SignatureConfig.register();
  }

  @Test
  public void testKeyManagerRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager(
                    "type.googleapis.com/google.crypto.tink.Ed25519PublicKey",
                    PublicKeyVerify.class))
        .isNotNull();
  }

  @Test
  public void test_serializeAndParse_works() throws Exception {
    KeysetHandle handle =
        KeysetHandle.generateNew(Ed25519Parameters.create()).getPublicKeysetHandle();
    byte[] serializedHandle = TinkProtoKeysetFormat.serializeKeysetWithoutSecret(handle);
    KeysetHandle parsedHandle = TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedHandle);
    assertThat(parsedHandle.equalsKeyset(handle)).isTrue();
  }
}
