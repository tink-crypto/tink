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
package com.google.crypto.tink.tinkkey.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.aead.AesEaxKeyManager;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.signature.Ed25519PrivateKeyManager;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for ProtoKey */
@RunWith(JUnit4.class)
public final class ProtoKeyTest {

  @Before
  public void setUp() throws GeneralSecurityException {
    AesEaxKeyManager.register(true);
    Ed25519PrivateKeyManager.registerPair(true);
  }

  @Test
  public void testProtoKey_keyDataSYMMETRIC_shouldHaveSecret() throws GeneralSecurityException {
    KeyTemplate kt = KeyTemplates.get("AES128_EAX");
    KeyData kd = Registry.newKeyData(kt);

    ProtoKey pk = new ProtoKey(kd, kt.getOutputPrefixType());

    assertThat(pk.getProtoKey()).isEqualTo(kd);
    assertThat(pk.getOutputPrefixType()).isEqualTo(kt.getOutputPrefixType());
    assertThat(pk.hasSecret()).isTrue();
  }

  @Test
  public void testProtoKey_keyDataASYMMETRICPRIVATE_shouldHaveSecret()
      throws GeneralSecurityException {
    KeyTemplate kt = KeyTemplates.get("ED25519");
    KeyData kd = Registry.newKeyData(kt);

    ProtoKey pk = new ProtoKey(kd, kt.getOutputPrefixType());

    assertThat(pk.getProtoKey()).isEqualTo(kd);
    assertThat(pk.getOutputPrefixType()).isEqualTo(kt.getOutputPrefixType());
    assertThat(pk.hasSecret()).isTrue();
  }

  @Test
  public void testProtoKey_keyDataUNKNOWN_shouldHaveSecret() throws GeneralSecurityException {
    KeyTemplate kt = KeyTemplates.get("ED25519");
    KeyData kd =
        KeyData.newBuilder()
            .mergeFrom(Registry.newKeyData(kt))
            .setKeyMaterialType(KeyData.KeyMaterialType.UNKNOWN_KEYMATERIAL)
            .build();

    ProtoKey pk = new ProtoKey(kd, kt.getOutputPrefixType());

    assertThat(pk.getProtoKey()).isEqualTo(kd);
    assertThat(pk.getOutputPrefixType()).isEqualTo(kt.getOutputPrefixType());
    assertThat(pk.hasSecret()).isTrue();
  }

  @Test
  public void testProtoKey_keyDataASYMMETRICPUBLIC_shouldNotHaveSecret()
      throws GeneralSecurityException {
    KeyTemplate kt = KeyTemplates.get("ED25519");
    KeyData kd = Registry.getPublicKeyData(kt.getTypeUrl(), Registry.newKeyData(kt).getValue());

    ProtoKey pk = new ProtoKey(kd, kt.getOutputPrefixType());

    assertThat(pk.getProtoKey()).isEqualTo(kd);
    assertThat(pk.getOutputPrefixType()).isEqualTo(kt.getOutputPrefixType());
    assertThat(pk.hasSecret()).isFalse();
  }

  @Test
  public void testProtoKey_keyDataREMOTE_shouldNotHaveSecret() throws GeneralSecurityException {
    KeyTemplate kt = KeyTemplates.get("ED25519");
    KeyData kd =
        KeyData.newBuilder()
            .mergeFrom(Registry.newKeyData(kt))
            .setKeyMaterialType(KeyData.KeyMaterialType.REMOTE)
            .build();

    ProtoKey pk = new ProtoKey(kd, kt.getOutputPrefixType());

    assertThat(pk.getProtoKey()).isEqualTo(kd);
    assertThat(pk.getOutputPrefixType()).isEqualTo(kt.getOutputPrefixType());
    assertThat(pk.hasSecret()).isFalse();
  }

  @Test
  public void testGetKeyTemplate_shouldThrow() throws GeneralSecurityException {
    KeyTemplate kt = AesEaxKeyManager.aes128EaxTemplate();
    KeyData kd = Registry.newKeyData(kt);
    ProtoKey pk = new ProtoKey(kd, kt.getOutputPrefixType());

    assertThrows(UnsupportedOperationException.class, pk::getKeyTemplate);
  }
}
