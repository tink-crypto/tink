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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.aead.AesEaxKeyManager;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.signature.Ed25519PrivateKeyManager;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import org.junit.Before;
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

  @Before
  public void setUp() throws Exception {
    AesEaxKeyManager.register(/* newKeyAllowed= */ true);
    Ed25519PrivateKeyManager.registerPair(/* newKeyAllowed= */ true);
  }

  @Test
  public void createFromKey_tinkKeyWithSecret_noSecretKeyAccess_shouldThrowException()
      throws Exception {
    TinkKey key = new DummyTinkKey(/* hasSecret= */ true);
    KeyAccess access = KeyAccess.publicAccess();

    assertThrows(GeneralSecurityException.class, () -> KeyHandle.createFromKey(key, access));
  }

  @Test
  public void createFromKey_keyDataSymmetric_shouldHaveSecret() throws Exception {
    KeyTemplate kt = KeyTemplates.get("AES128_EAX");
    KeyData kd = Registry.newKeyData(kt);

    KeyHandle kh = KeyHandle.createFromKey(kd, kt.getOutputPrefixType());

    assertThat(kh.hasSecret()).isTrue();
  }

  @Test
  public void createFromKey_keyDataAsymmetricPrivate_shouldHaveSecret() throws Exception {
    KeyTemplate kt = KeyTemplates.get("ED25519");
    KeyData kd = Registry.newKeyData(kt);

    KeyHandle kh = KeyHandle.createFromKey(kd, kt.getOutputPrefixType());

    assertThat(kh.hasSecret()).isTrue();
  }

  @Test
  public void createFromKey_keyDataUnknown_shouldHaveSecret() throws Exception {
    KeyTemplate kt = KeyTemplates.get("ED25519");
    KeyData kd =
        KeyData.newBuilder()
            .mergeFrom(Registry.newKeyData(kt))
            .setKeyMaterialType(KeyData.KeyMaterialType.UNKNOWN_KEYMATERIAL)
            .build();

    KeyHandle kh = KeyHandle.createFromKey(kd, kt.getOutputPrefixType());

    assertThat(kh.hasSecret()).isTrue();
  }

  @Test
  public void createFromKey_keyDataAsymmetricPublic_shouldNotHaveSecret() throws Exception {
    KeyTemplate kt = KeyTemplates.get("ED25519");
    KeyData kd = Registry.getPublicKeyData(kt.getTypeUrl(), Registry.newKeyData(kt).getValue());

    KeyHandle kh = KeyHandle.createFromKey(kd, kt.getOutputPrefixType());

    assertThat(kh.hasSecret()).isFalse();
  }

  @Test
  public void createFromKey_keyDataRemote_shouldNotHaveSecret() throws Exception {
    KeyTemplate kt = KeyTemplates.get("ED25519");
    KeyData kd =
        KeyData.newBuilder()
            .mergeFrom(Registry.newKeyData(kt))
            .setKeyMaterialType(KeyData.KeyMaterialType.REMOTE)
            .build();

    KeyHandle kh = KeyHandle.createFromKey(kd, kt.getOutputPrefixType());

    assertThat(kh.hasSecret()).isFalse();
  }

  @Test
  public void hasSecret_tinkKeyWithSecret_shouldReturnTrue() throws Exception {
    TinkKey key = new DummyTinkKey(/* hasSecret= */ true);
    KeyAccess access = SecretKeyAccess.insecureSecretAccess();
    KeyHandle kh = KeyHandle.createFromKey(key, access);

    assertThat(kh.hasSecret()).isTrue();
  }

  @Test
  public void hasSecret_tinkKeyWithoutSecret_shouldReturnFalse() throws Exception {
    TinkKey key = new DummyTinkKey(/* hasSecret= */ false);
    KeyAccess access = KeyAccess.publicAccess();
    KeyHandle kh = KeyHandle.createFromKey(key, access);

    assertThat(kh.hasSecret()).isFalse();
  }

  @Test
  public void getKey_tinkKeyWithoutSecret_noSecretKeyAccess_shouldWork() throws Exception {
    TinkKey key = new DummyTinkKey(/* hasSecret= */ false);
    KeyAccess access = KeyAccess.publicAccess();
    KeyHandle kh = KeyHandle.createFromKey(key, access);

    assertThat(kh.getKey(access)).isEqualTo(key);
  }

  @Test
  public void getKey_tinkKeyWithoutSecret_secretKeyAccess_shouldWork() throws Exception {
    TinkKey key = new DummyTinkKey(/* hasSecret= */ false);
    KeyAccess access = SecretKeyAccess.insecureSecretAccess();
    KeyHandle kh = KeyHandle.createFromKey(key, access);

    assertThat(kh.getKey(access)).isEqualTo(key);
  }

  @Test
  public void getKey_tinkKeyWithSecret_noSecretKeyAccess_shouldThrowException() throws Exception {
    TinkKey key = new DummyTinkKey(/* hasSecret= */ true);
    KeyAccess access = SecretKeyAccess.insecureSecretAccess();
    KeyHandle kh = KeyHandle.createFromKey(key, access);
    KeyAccess pubAccess = KeyAccess.publicAccess();

    assertThrows(GeneralSecurityException.class, () -> kh.getKey(pubAccess));
  }

  @Test
  public void getKey_tinkKeyWithSecret_secretKeyAccess_shouldWork() throws Exception {
    TinkKey key = new DummyTinkKey(/* hasSecret= */ true);
    KeyAccess access = SecretKeyAccess.insecureSecretAccess();
    KeyHandle kh = KeyHandle.createFromKey(key, access);

    assertThat(kh.getKey(access)).isEqualTo(key);
  }
}
