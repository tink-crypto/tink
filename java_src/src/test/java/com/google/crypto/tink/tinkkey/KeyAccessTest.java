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
package com.google.crypto.tink.tinkkey;

import static com.google.common.truth.Truth.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for KeyAccess **/
@RunWith(JUnit4.class)
public final class KeyAccessTest {

  @Test
  public void testPublicAccess_shouldReturnKeyAccessWithoutSecretAccess() {
    assertThat(KeyAccess.publicAccess().canAccessSecret()).isFalse();
  }

  @Test
  public void testSecretAccess_shouldReturnKeyAccessWithSecretAccess() {
    assertThat(KeyAccess.secretAccess().canAccessSecret()).isTrue();
  }
}
