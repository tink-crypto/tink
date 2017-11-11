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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.Config;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.proto.RegistryConfig;
import java.security.GeneralSecurityException;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.junit.runners.MethodSorters;

/**
 * Tests for StreamingAeadConfig. Using FixedMethodOrder to ensure that aaaTestInitialization runs
 * first, as it tests execution of a static block within StreamingAeadConfig-class.
 */
@RunWith(JUnit4.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class StreamingAeadConfigTest {

  // This test must run first.
  @Test
  public void aaaTestInitialization() throws Exception {
    try {
      Registry.getCatalogue("tinkstreamingaead");
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("no catalogue found");
      assertThat(e.toString()).contains("StreamingAeadConfig.init()");
    }
    try {
      Registry.getCatalogue("TinkStreamingAead");
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("no catalogue found");
      assertThat(e.toString()).contains("StreamingAeadConfig.init()");
    }
    // Get the config proto, now the catalogues should be present,
    // as init() was triggered by a static block.
    RegistryConfig unused = StreamingAeadConfig.TINK_1_1_0;
    Registry.getCatalogue("TinkStreamingAead");

    // Running init() manually again should succeed.
    StreamingAeadConfig.init();
  }

  @Test
  public void testConfigContents() throws Exception {
    RegistryConfig config = StreamingAeadConfig.TINK_1_1_0;
    assertEquals(2, config.getEntryCount());
    assertEquals("TINK_STREAMINGAEAD_1_1_0", config.getConfigName());

    TestUtil.verifyConfigEntry(
        config.getEntry(0),
        "TinkStreamingAead",
        "StreamingAead",
        "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
        true,
        0);
    TestUtil.verifyConfigEntry(
        config.getEntry(1),
        "TinkStreamingAead",
        "StreamingAead",
        "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey",
        true,
        0);
  }

  @Test
  public void testRegistration() throws Exception {
    String typeUrl = "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey";
    try {
      Registry.getKeyManager(typeUrl);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("No key manager found");
    }
    // After registration the key manager should be present.
    Config.register(StreamingAeadConfig.TINK_1_1_0);
    Registry.getKeyManager(typeUrl);
  }
}
