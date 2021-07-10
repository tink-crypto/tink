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

import com.google.common.truth.Expect;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplate.OutputPrefixType;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.aead.AesEaxKeyManager;
import com.google.crypto.tink.proto.AesEaxKey;
import com.google.crypto.tink.proto.AesEaxKeyFormat;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.signature.Ed25519PrivateKeyManager;
import com.google.crypto.tink.tinkkey.internal.ProtoKey;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for KeyHandle * */
@RunWith(JUnit4.class)
public final class KeyHandleTest {

  @Rule public final Expect expect = Expect.create();

  @Immutable
  static final class DummyTinkKey implements TinkKey {
    private final boolean hasSecret;
    private final KeyTemplate template;

    public DummyTinkKey(boolean hasSecret) {
      this.hasSecret = hasSecret;
      this.template = null;
    }

    public DummyTinkKey(boolean hasSecret, KeyTemplate template) {
      this.hasSecret = hasSecret;
      this.template = template;
    }

    @Override
    public boolean hasSecret() {
      return hasSecret;
    }

    @Override
    public KeyTemplate getKeyTemplate() {
      if (template == null) {
        throw new UnsupportedOperationException();
      }
      return template;
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
  public void generateNew_shouldWork() throws Exception {
    KeyTemplate template = KeyTemplates.get("AES128_EAX");

    KeyHandle handle = KeyHandle.generateNew(template);

    ProtoKey protoKey = (ProtoKey) handle.getKey(SecretKeyAccess.insecureSecretAccess());
    expect.that(protoKey.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.TINK);
    expect.that(protoKey.hasSecret()).isTrue();
    KeyData keyData = protoKey.getProtoKey();
    expect.that(keyData.getTypeUrl()).isEqualTo(template.getTypeUrl());
    AesEaxKeyFormat aesEaxKeyFormat =
        AesEaxKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    AesEaxKey aesEaxKey =
        AesEaxKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    expect.that(aesEaxKey.getKeyValue().size()).isEqualTo(aesEaxKeyFormat.getKeySize());
  }

  @Test
  public void generateNew_compareWith_createFromKeyViaProtoKey_shouldBeEqual() throws Exception {
    KeyTemplate template = KeyTemplates.get("AES128_EAX");
    KeyData keyData = Registry.newKeyData(template);
    ProtoKey protoKey = new ProtoKey(keyData, template.getOutputPrefixType());

    KeyHandle handle1 = KeyHandle.generateNew(template);
    KeyHandle handle2 = KeyHandle.createFromKey(protoKey, SecretKeyAccess.insecureSecretAccess());

    expect.that(handle1.getStatus()).isEqualTo(handle2.getStatus());
    ProtoKey outputProtoKey1 = (ProtoKey) handle1.getKey(SecretKeyAccess.insecureSecretAccess());
    ProtoKey outputProtoKey2 = (ProtoKey) handle2.getKey(SecretKeyAccess.insecureSecretAccess());
    expect
        .that(outputProtoKey1.getOutputPrefixType())
        .isEqualTo(outputProtoKey2.getOutputPrefixType());
    expect.that(handle1.hasSecret()).isEqualTo(handle2.hasSecret());
  }

  @Test
  public void generateNew_generatesDifferentKeys() throws Exception {
    KeyTemplate template = KeyTemplates.get("AES128_EAX");
    Set<String> keys = new TreeSet<>();

    int numKeys = 2;
    for (int j = 0; j < numKeys; j++) {
      KeyHandle handle = KeyHandle.generateNew(template);
      ProtoKey protoKey = (ProtoKey) handle.getKey(SecretKeyAccess.insecureSecretAccess());
      KeyData keyData = protoKey.getProtoKey();
      AesEaxKey aesEaxKey =
          AesEaxKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      keys.add(aesEaxKey.getKeyValue().toStringUtf8());
    }

    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void generateNew_unregisteredTypeUrl_shouldThrow() throws Exception {
    String typeUrl = "testNewKeyDataTypeUrl";
    ByteString keyformat = ByteString.copyFromUtf8("testNewKeyDataKeyFormat");
    com.google.crypto.tink.KeyTemplate keyTemplate =
        com.google.crypto.tink.KeyTemplate.create(
            typeUrl, keyformat.toByteArray(), OutputPrefixType.TINK);

    assertThrows(GeneralSecurityException.class, () -> KeyHandle.generateNew(keyTemplate));
  }

  @Test
  public void hasSecret_tinkKeyWithSecret_shouldReturnTrue() throws Exception {
    TinkKey key = new DummyTinkKey(/* hasSecret= */ true);
    KeyHandle kh = KeyHandle.createFromKey(key, SecretKeyAccess.insecureSecretAccess());

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
    KeyHandle kh = KeyHandle.createFromKey(key, SecretKeyAccess.insecureSecretAccess());
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

  @Test
  public void getKeyTemplate() throws Exception {
    KeyTemplate keyTemplate = KeyTemplates.get("ED25519_RAW");
    TinkKey key = new DummyTinkKey(/* hasSecret= */ false, keyTemplate);
    KeyHandle keyHandle = KeyHandle.createFromKey(key, KeyAccess.publicAccess());

    KeyTemplate returnedKeyTemplate = keyHandle.getKeyTemplate();

    assertThat(returnedKeyTemplate.getValue()).isEqualTo(keyTemplate.getValue());
  }

  @Test
  public void getKeyTemplate_tinkKeyWithoutKeyTemplateSupport_shouldThrow() throws Exception {
    TinkKey key = new DummyTinkKey(/* hasSecret= */ false);
    KeyHandle keyHandle = KeyHandle.createFromKey(key, KeyAccess.publicAccess());

    assertThrows(UnsupportedOperationException.class, keyHandle::getKeyTemplate);
  }
}
