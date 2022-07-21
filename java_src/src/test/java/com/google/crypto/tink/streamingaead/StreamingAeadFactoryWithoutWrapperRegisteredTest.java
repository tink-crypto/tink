// Copyright 2022 Google LLC
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

package com.google.crypto.tink.streamingaead;

import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.testing.StreamingTestUtil;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit test for {@link StreamingAeadFactory}.
 *
 * <p>The test case in this file needs {@link Registry} to not have {@link StreamingAeadWrapper}
 * registered. That's why it is in its own test file.
 */
@RunWith(JUnit4.class)
public class StreamingAeadFactoryWithoutWrapperRegisteredTest {

  @Test
  @SuppressWarnings("deprecation") // This is a test that the deprecated function works.
  public void deprecatedFactoryGetPrimitive_whenWrapperHasNotBeenRegistered_works()
      throws Exception {
    // Only register AesCtrHmacStreamingKeyManager, but not the StreamingAeadWrapper.
    AesCtrHmacStreamingKeyManager.register(/* newKeyAllowed = */ true);
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("AES128_CTR_HMAC_SHA256_4KB"));

    StreamingAead streamingAead = StreamingAeadFactory.getPrimitive(handle);

    StreamingTestUtil.testEncryptionAndDecryption(streamingAead);
  }
}
