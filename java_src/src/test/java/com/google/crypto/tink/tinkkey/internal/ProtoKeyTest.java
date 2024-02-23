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
import static com.google.crypto.tink.internal.KeyTemplateProtoConverter.getOutputPrefixType;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.PrivateKeyManager;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.aead.AesEaxKeyManager;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.signature.Ed25519PrivateKeyManager;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for ProtoKey */
@RunWith(JUnit4.class)
public final class ProtoKeyTest {
  private static KeyData newKeyData(com.google.crypto.tink.KeyTemplate keyTemplate)
      throws GeneralSecurityException {
    try {
      byte[] serializedKeyTemplate =
          TinkProtoParametersFormat.serialize(keyTemplate.toParameters());
      com.google.crypto.tink.proto.KeyTemplate protoTemplate =
          com.google.crypto.tink.proto.KeyTemplate.parseFrom(
              serializedKeyTemplate, ExtensionRegistryLite.getEmptyRegistry());
      KeyManager<?> manager =
          KeyManagerRegistry.globalInstance().getUntypedKeyManager(protoTemplate.getTypeUrl());
      if (KeyManagerRegistry.globalInstance().isNewKeyAllowed(protoTemplate.getTypeUrl())) {
        return manager.newKeyData(protoTemplate.getValue());
      } else {
        throw new GeneralSecurityException(
            "newKey-operation not permitted for key type " + protoTemplate.getTypeUrl());
      }
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Failed to parse serialized parameters", e);
    }
  }

  private static KeyData getPublicKeyData(String typeUrl, ByteString serializedPrivateKey)
      throws GeneralSecurityException {
    KeyManager<?> manager = KeyManagerRegistry.globalInstance().getUntypedKeyManager(typeUrl);

    if (!(manager instanceof PrivateKeyManager)) {
      throw new GeneralSecurityException(
          "manager for key type " + typeUrl + " is not a PrivateKeyManager");
    }
    return ((PrivateKeyManager) manager).getPublicKeyData(serializedPrivateKey);
  }

  @Before
  public void setUp() throws GeneralSecurityException {
    AesEaxKeyManager.register(true);
    Ed25519PrivateKeyManager.registerPair(true);
  }

  @Test
  public void testProtoKey_keyDataSYMMETRIC_shouldHaveSecret() throws GeneralSecurityException {
    KeyTemplate kt = KeyTemplates.get("AES128_EAX");
    KeyData kd = newKeyData(kt);

    ProtoKey pk = new ProtoKey(kd, getOutputPrefixType(kt));

    assertThat(pk.getProtoKey()).isEqualTo(kd);
    assertThat(pk.getOutputPrefixType()).isEqualTo(getOutputPrefixType(kt));
    assertThat(pk.hasSecret()).isTrue();
  }

  @Test
  public void testProtoKey_keyDataASYMMETRICPRIVATE_shouldHaveSecret()
      throws GeneralSecurityException {
    KeyTemplate kt = KeyTemplates.get("ED25519");
    KeyData kd = newKeyData(kt);

    ProtoKey pk = new ProtoKey(kd, getOutputPrefixType(kt));

    assertThat(pk.getProtoKey()).isEqualTo(kd);
    assertThat(pk.getOutputPrefixType()).isEqualTo(getOutputPrefixType(kt));
    assertThat(pk.hasSecret()).isTrue();
  }

  @Test
  public void testProtoKey_keyDataUNKNOWN_shouldHaveSecret() throws GeneralSecurityException {
    KeyTemplate kt = KeyTemplates.get("ED25519");
    KeyData kd =
        newKeyData(kt).toBuilder()
            .setKeyMaterialType(KeyData.KeyMaterialType.UNKNOWN_KEYMATERIAL)
            .build();

    ProtoKey pk = new ProtoKey(kd, getOutputPrefixType(kt));

    assertThat(pk.getProtoKey()).isEqualTo(kd);
    assertThat(pk.getOutputPrefixType()).isEqualTo(getOutputPrefixType(kt));
    assertThat(pk.hasSecret()).isTrue();
  }

  @Test
  public void testProtoKey_keyDataASYMMETRICPUBLIC_shouldNotHaveSecret()
      throws GeneralSecurityException {
    KeyTemplate kt = KeyTemplates.get("ED25519");
    KeyData privateKeyData = newKeyData(kt);
    KeyData kd = getPublicKeyData(privateKeyData.getTypeUrl(), privateKeyData.getValue());

    ProtoKey pk = new ProtoKey(kd, getOutputPrefixType(kt));

    assertThat(pk.getProtoKey()).isEqualTo(kd);
    assertThat(pk.getOutputPrefixType()).isEqualTo(getOutputPrefixType(kt));
    assertThat(pk.hasSecret()).isFalse();
  }

  @Test
  public void testProtoKey_keyDataREMOTE_shouldNotHaveSecret() throws GeneralSecurityException {
    KeyTemplate kt = KeyTemplates.get("ED25519");
    KeyData kd =
        newKeyData(kt).toBuilder().setKeyMaterialType(KeyData.KeyMaterialType.REMOTE).build();

    ProtoKey pk = new ProtoKey(kd, getOutputPrefixType(kt));

    assertThat(pk.getProtoKey()).isEqualTo(kd);
    assertThat(pk.getOutputPrefixType()).isEqualTo(getOutputPrefixType(kt));
    assertThat(pk.hasSecret()).isFalse();
  }

  @Test
  public void testGetKeyTemplate_shouldThrow() throws GeneralSecurityException {
    KeyTemplate kt = AesEaxKeyManager.aes128EaxTemplate();
    KeyData kd = newKeyData(kt);
    ProtoKey pk = new ProtoKey(kd, getOutputPrefixType(kt));

    assertThrows(UnsupportedOperationException.class, pk::getKeyTemplate);
  }
}
