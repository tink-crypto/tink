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
      assertThat(e.toString()).contains("StreamingAeadConfig.register()");
    }
    try {
      Registry.getCatalogue("TinkStreamingAead");
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("no catalogue found");
      assertThat(e.toString()).contains("StreamingAeadConfig.register()");
    }
    String typeUrl = "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey";
    try {
      Registry.getKeyManager(typeUrl);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("No key manager found");
    }

    // Initialize the config.
    StreamingAeadConfig.register();

    // Now the catalogues should be present.
    Registry.getCatalogue("TinkStreamingAead");

    // After registration the key manager should be present.
    Registry.getKeyManager(typeUrl);

    // Running init() manually again should succeed.
    StreamingAeadConfig.register();
  }

  @Test
  public void testConfigContents_1_1_0() throws Exception {
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
  public void testConfigContents_LATEST() throws Exception {
    RegistryConfig config = StreamingAeadConfig.LATEST;
    assertEquals(2, config.getEntryCount());
    assertEquals("TINK_STREAMINGAEAD", config.getConfigName());

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
}
