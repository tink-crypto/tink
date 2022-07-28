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

package com.google.crypto.tink.streamingaead;

import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.testing.StreamingTestUtil;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for StreamingAeadFactory. */
@RunWith(JUnit4.class)
public class StreamingAeadFactoryTest {

  @BeforeClass
  public static void setUp() throws Exception {
    StreamingAeadConfig.register();
  }

  @Test
  @SuppressWarnings("deprecation") // This is a test that the deprecated function works.
  public void deprecatedMacFactoryGetPrimitive_sameAs_keysetHandleGetPrimitive() throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("AES128_CTR_HMAC_SHA256_4KB"));

    StreamingAead streamingAead = handle.getPrimitive(StreamingAead.class);
    StreamingAead factoryStreamingAead = StreamingAeadFactory.getPrimitive(handle);

    StreamingTestUtil.testEncryptionAndDecryption(streamingAead, factoryStreamingAead);
    StreamingTestUtil.testEncryptionAndDecryption(factoryStreamingAead, streamingAead);
  }
}
