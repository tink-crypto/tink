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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyTemplate;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for KeyHandle * */
@RunWith(JUnit4.class)
public final class KeyHandleTest {

  @Immutable
  static final class DummyTinkKey implements TinkKey {
    private final boolean hasSecret;

    public DummyTinkKey(boolean hasSecret) {
      this.hasSecret = hasSecret;
    }

    @Override
    public boolean hasSecret() {
      return hasSecret;
    }

    @Override
    public KeyTemplate getKeyTemplate() {
      throw new UnsupportedOperationException();
    }
  }

  @Test
  public void testCreateFromKey_tinkKeyWithSecret_noSecretKeyAccess_shouldThrowException()
      throws Exception {
    TinkKey key = new DummyTinkKey(true);
    KeyAccess access = KeyAccess.publicAccess();

    assertThrows(GeneralSecurityException.class, () -> KeyHandle.createFromKey(key, access));
  }

  @Test
  public void testHasSecret_tinkKeyWithSecret_shouldReturnTrue() throws Exception {
    TinkKey key = new DummyTinkKey(true);
    KeyAccess access = SecretKeyAccess.insecureSecretAccess();
    KeyHandle kh = KeyHandle.createFromKey(key, access);

    assertThat(kh.hasSecret()).isTrue();
  }

  @Test
  public void testHasSecret_tinkKeyWithoutSecret_shouldReturnFalse() throws Exception {
    TinkKey key = new DummyTinkKey(false);
    KeyAccess access = KeyAccess.publicAccess();
    KeyHandle kh = KeyHandle.createFromKey(key, access);

    assertThat(kh.hasSecret()).isFalse();
  }

  @Test
  public void testGetKey_tinkKeyWithoutSecret_noSecretKeyAccess_shouldWork() throws Exception {
    TinkKey key = new DummyTinkKey(false);
    KeyAccess access = KeyAccess.publicAccess();
    KeyHandle kh = KeyHandle.createFromKey(key, access);

    assertThat(kh.getKey(access)).isEqualTo(key);
  }

  @Test
  public void testGetKey_tinkKeyWithoutSecret_secretKeyAccess_shouldWork() throws Exception {
    TinkKey key = new DummyTinkKey(false);
    KeyAccess access = SecretKeyAccess.insecureSecretAccess();
    KeyHandle kh = KeyHandle.createFromKey(key, access);

    assertThat(kh.getKey(access)).isEqualTo(key);
  }

  @Test
  public void testGetKey_tinkKeyWithSecret_noSecretKeyAccess_shouldThrowException()
      throws Exception {
    TinkKey key = new DummyTinkKey(true);
    KeyAccess access = SecretKeyAccess.insecureSecretAccess();
    KeyHandle kh = KeyHandle.createFromKey(key, access);
    KeyAccess pubAccess = KeyAccess.publicAccess();

    assertThrows(GeneralSecurityException.class, () -> kh.getKey(pubAccess));
  }

  @Test
  public void testGetKey_tinkKeyWithSecret_secretKeyAccess_shouldWork() throws Exception {
    TinkKey key = new DummyTinkKey(true);
    KeyAccess access = SecretKeyAccess.insecureSecretAccess();
    KeyHandle kh = KeyHandle.createFromKey(key, access);

    assertThat(kh.getKey(access)).isEqualTo(key);
  }
}
