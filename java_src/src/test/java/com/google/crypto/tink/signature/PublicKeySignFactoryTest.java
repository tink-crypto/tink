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

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link PublicKeySignFactory}. */
@RunWith(JUnit4.class)
public class PublicKeySignFactoryTest {

  @BeforeClass
  public static void setUp() throws Exception {
    SignatureConfig.register();
  }

  @Test
  @SuppressWarnings("deprecation") // This is a test that the deprecated function works.
  public void deprecatedPublicKeySignFactoryGetPrimitive_sameAs_keysetHandleGetPrimitive()
      throws Exception {
    KeysetHandle privateHandle = KeysetHandle.generateNew(KeyTemplates.get("ECDSA_P256"));
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

    PublicKeySign factorySigner = PublicKeySignFactory.getPrimitive(privateHandle);
    PublicKeySign handleSigner = privateHandle.getPrimitive(PublicKeySign.class);

    PublicKeyVerify verifier = publicHandle.getPrimitive(PublicKeyVerify.class);

    byte[] data = "data".getBytes(UTF_8);
    byte[] factorySig = factorySigner.sign(data);
    byte[] handleSig = handleSigner.sign(data);

    verifier.verify(factorySig, data);
    verifier.verify(handleSig, data);
  }
}
