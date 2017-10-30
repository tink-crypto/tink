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

package com.google.crypto.tink.apps.paymentmethodtoken;

import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link GooglePaymentsPublicKeysManager}. */
@RunWith(JUnit4.class)
public class GooglePaymentsPublicKeyManagerTest {
  @Test
  public void builderShouldReturnSingletonsWhenMatching() {
    assertSame(
        GooglePaymentsPublicKeysManager.INSTANCE_PRODUCTION,
        new GooglePaymentsPublicKeysManager.Builder().build());
    assertSame(
        GooglePaymentsPublicKeysManager.INSTANCE_TEST,
        new GooglePaymentsPublicKeysManager.Builder()
            .setKeysUrl(GooglePaymentsPublicKeysManager.KEYS_URL_TEST)
            .build());
  }

  @Test
  public void builderShouldReturnDifferentInstanceWhenNotMatchingSingletons() {
    assertNotSame(
        GooglePaymentsPublicKeysManager.INSTANCE_PRODUCTION,
        new GooglePaymentsPublicKeysManager.Builder().setKeysUrl("https://abc").build());
    assertNotSame(
        GooglePaymentsPublicKeysManager.INSTANCE_TEST,
        new GooglePaymentsPublicKeysManager.Builder().setKeysUrl("https://abc").build());
  }

  @Test
  public void builderShouldThrowIllegalArgumentExceptionWhenUrlIsNotHttps() {
    try {
      new GooglePaymentsPublicKeysManager.Builder().setKeysUrl("http://abc").build();
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException ex) {
      // expected.
    }
  }
}
