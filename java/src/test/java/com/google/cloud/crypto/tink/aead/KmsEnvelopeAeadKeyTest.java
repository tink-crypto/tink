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

package com.google.cloud.crypto.tink.aead;

import com.google.cloud.crypto.tink.Aead;
import com.google.cloud.crypto.tink.KeysetHandle;
import com.google.cloud.crypto.tink.GoogleCloudKmsProto.GoogleCloudKmsAeadKey;
import com.google.cloud.crypto.tink.KmsEnvelopeProto.KmsEnvelopeAeadKey;
import com.google.cloud.crypto.tink.TestGoogleCredentialFactory;
import com.google.cloud.crypto.tink.TestUtil;
import com.google.cloud.crypto.tink.TinkProto.KeyFormat;
import com.google.cloud.crypto.tink.TinkProto.OutputPrefixType;
import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import com.google.cloud.crypto.tink.Registry;
import com.google.protobuf.Any;
import java.io.IOException;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests for {@code KmsEnvelopeAead} and {@code KmsEnvelopeAeadKeyManager}.
 */
public class KmsEnvelopeAeadKeyTest {

  @Before
  public void setUp() throws GeneralSecurityException {
    AeadFactory.registerStandardKeyTypes();
    Registry.INSTANCE.registerKeyManager(
        "type.googleapis.com/google.cloud.crypto.tink.GoogleCloudKmsAeadKey",
        new GoogleCloudKmsAeadKeyManager(new TestGoogleCredentialFactory()));
  }

  @Test
  public void testGoogleCloudKmsKeyRestricted() throws Exception {
    // This key is restricted, use the cred of
    // tink-unit-tests@testing-cloud-kms-159306.iam.gserviceaccount.com.
    int aesKeySize = 16;
    int ivSize = 16;
    int hmacKeySize = 16;
    int tagSize = 16;
    KeyFormat dekFormat = TestUtil.createAesCtrHmacAeadKeyFormat(
        aesKeySize, ivSize, hmacKeySize, tagSize);
    Any kmsKey = Any.pack(TestUtil.createGoogleCloudKmsAeadKey(
        TestGoogleCredentialFactory.RESTRICTED));
    KmsEnvelopeAeadKey kmsEnvelopeAeadKey = TestUtil.createKmsEnvelopeAeadKey(kmsKey, dekFormat);
    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(
            TestUtil.createKey(kmsEnvelopeAeadKey, 42,
                KeyStatusType.ENABLED, OutputPrefixType.TINK)));

    Aead aead = AeadFactory.getPrimitive(keysetHandle);
    TestUtil.runBasicTests(aead);
  }
}
