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

package com.google.crypto.tink;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link SecretKeyAccess} */
@RunWith(JUnit4.class)
public final class SecretKeyAccessTest {
  @Test
  public void testGet_notNull() {
    assertThat(InsecureSecretKeyAccess.get()).isNotNull();
  }

  @Test
  public void testRequireAccess_worksAndReturnsObject() throws Exception {
    assertThat(SecretKeyAccess.requireAccess(InsecureSecretKeyAccess.get()))
        .isEqualTo(InsecureSecretKeyAccess.get());
  }

  @Test
  public void testRequireAccess_throwsIfNull() throws Exception {
    assertThrows(
        GeneralSecurityException.class, () -> SecretKeyAccess.requireAccess(/* access = */ null));
  }
}
