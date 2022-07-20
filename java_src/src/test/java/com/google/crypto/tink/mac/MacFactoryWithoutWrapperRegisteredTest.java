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

package com.google.crypto.tink.mac;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit test for {@link MacFactory}.
 *
 * <p>The test case in this file needs {@link Registry} to not have {@link MacWrapper} registered.
 * That's why it is in its own test file.
 */
@RunWith(JUnit4.class)
public class MacFactoryWithoutWrapperRegisteredTest {

  @Test
  @SuppressWarnings("deprecation") // This is a test that the deprecated function works.
  public void deprecatedFactoryGetPrimitive_whenWrapperHasNotBeenRegistered_works()
      throws Exception {
    // Only register HmacKeyManager, but not the MacWrapper.
    HmacKeyManager.register(/* newKeyAllowed = */ true);
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("HMAC_SHA256_128BITTAG"));

    Mac mac = MacFactory.getPrimitive(handle);

    byte[] data = "data".getBytes(UTF_8);
    byte[] tag = mac.computeMac(data);
    mac.verifyMac(tag, data);
  }
}
