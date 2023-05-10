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

package com.google.crypto.tink.keyderivation.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.aead.AesGcmKeyManager;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.keyderivation.KeysetDeriver;
import com.google.crypto.tink.prf.HkdfPrfKeyManager;
import com.google.crypto.tink.proto.AesGcmKey;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HkdfPrfKey;
import com.google.crypto.tink.proto.HkdfPrfKeyFormat;
import com.google.crypto.tink.proto.HkdfPrfParams;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.PrfBasedDeriverKey;
import com.google.crypto.tink.proto.PrfBasedDeriverKeyFormat;
import com.google.crypto.tink.proto.PrfBasedDeriverParams;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test for PrfBasedDeriverKeyManager. */
@RunWith(JUnit4.class)
public class PrfBasedDeriverKeyManagerTest {
  private final PrfBasedDeriverKeyManager manager = new PrfBasedDeriverKeyManager();
  private final KeyTypeManager.KeyFactory<PrfBasedDeriverKeyFormat, PrfBasedDeriverKey> factory =
      manager.keyFactory();

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    TinkConfig.register();
  }

  @Test
  public void basics() throws Exception {
    assertThat(manager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey");
    assertThat(manager.getVersion()).isEqualTo(0);
    assertThat(manager.keyMaterialType()).isEqualTo(KeyMaterialType.SYMMETRIC);
  }

  @Test
  public void validateKey_empty() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> manager.validateKey(PrfBasedDeriverKey.getDefaultInstance()));
  }

  @Test
  public void validateKey_valid() throws Exception {
    HkdfPrfKey prfKey =
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(10)))
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build();
    PrfBasedDeriverKey key =
        PrfBasedDeriverKey.newBuilder()
            .setPrfKey(
                TestUtil.createKeyData(
                    prfKey, HkdfPrfKeyManager.staticKeyType(), KeyMaterialType.SYMMETRIC))
            .setParams(
                PrfBasedDeriverParams.newBuilder()
                    .setDerivedKeyTemplate(AeadKeyTemplates.AES256_GCM))
            .build();
    manager.validateKey(key);
  }

  @Test
  public void validateKey_wrongVersion_throws() throws Exception {
    HkdfPrfKey prfKey =
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(10)))
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build();
    PrfBasedDeriverKey key =
        PrfBasedDeriverKey.newBuilder()
            .setPrfKey(
                TestUtil.createKeyData(
                    prfKey, HkdfPrfKeyManager.staticKeyType(), KeyMaterialType.SYMMETRIC))
            .setParams(
                PrfBasedDeriverParams.newBuilder()
                    .setDerivedKeyTemplate(AeadKeyTemplates.AES256_GCM))
            .setVersion(1)
            .build();
    assertThrows(GeneralSecurityException.class, () -> manager.validateKey(key));
  }

  @Test
  public void validateKeyFormat_empty() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(PrfBasedDeriverKeyFormat.getDefaultInstance()));
  }

  @Test
  public void validateKeyFormat_valid() throws Exception {
    HkdfPrfKeyFormat prfKeyFormat =
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build();
    PrfBasedDeriverKeyFormat keyFormat =
        PrfBasedDeriverKeyFormat.newBuilder()
            .setPrfKeyTemplate(
                KeyTemplate.newBuilder()
                    .setTypeUrl(HkdfPrfKeyManager.staticKeyType())
                    .setValue(prfKeyFormat.toByteString()))
            .setParams(
                PrfBasedDeriverParams.newBuilder()
                    .setDerivedKeyTemplate(AeadKeyTemplates.AES256_GCM))
            .build();
    factory.validateKeyFormat(keyFormat);
  }

  @Test
  public void createKey_checkValues() throws Exception {
    HkdfPrfKeyManager.register(true);
    HkdfPrfKeyFormat prfKeyFormat =
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build();
    PrfBasedDeriverKeyFormat keyFormat =
        PrfBasedDeriverKeyFormat.newBuilder()
            .setPrfKeyTemplate(
                KeyTemplate.newBuilder()
                    .setTypeUrl(HkdfPrfKeyManager.staticKeyType())
                    .setValue(prfKeyFormat.toByteString()))
            .setParams(
                PrfBasedDeriverParams.newBuilder()
                    .setDerivedKeyTemplate(AeadKeyTemplates.AES256_GCM))
            .build();
    PrfBasedDeriverKey key = factory.createKey(keyFormat);

    assertThat(key.getVersion()).isEqualTo(0);
    assertThat(key.getPrfKey().getTypeUrl()).isEqualTo(HkdfPrfKeyManager.staticKeyType());
    assertThat(key.getPrfKey().getKeyMaterialType()).isEqualTo(KeyMaterialType.SYMMETRIC);
    HkdfPrfKey hkdfPrfKey =
        HkdfPrfKey.parseFrom(key.getPrfKey().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(hkdfPrfKey.getKeyValue()).hasSize(32);
    assertThat(key.getParams()).isEqualTo(keyFormat.getParams());
  }

  @Test
  public void createKey_invalidPrfKey_throws() throws Exception {
    HkdfPrfKeyManager.register(true);
    HkdfPrfKeyFormat prfKeyFormat =
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.UNKNOWN_HASH))
            .build();
    PrfBasedDeriverKeyFormat keyFormat =
        PrfBasedDeriverKeyFormat.newBuilder()
            .setPrfKeyTemplate(
                KeyTemplate.newBuilder()
                    .setTypeUrl(HkdfPrfKeyManager.staticKeyType())
                    .setValue(prfKeyFormat.toByteString()))
            .setParams(
                PrfBasedDeriverParams.newBuilder()
                    .setDerivedKeyTemplate(AeadKeyTemplates.AES256_GCM))
            .build();
    assertThrows(GeneralSecurityException.class, () -> factory.createKey(keyFormat));
  }

  @Test
  public void createKey_invalidDerivedKeyTemplate_throws() throws Exception {
    HkdfPrfKeyManager.register(true);
    HkdfPrfKeyFormat prfKeyFormat =
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build();
    PrfBasedDeriverKeyFormat keyFormat =
        PrfBasedDeriverKeyFormat.newBuilder()
            .setPrfKeyTemplate(
                KeyTemplate.newBuilder()
                    .setTypeUrl(HkdfPrfKeyManager.staticKeyType())
                    .setValue(prfKeyFormat.toByteString()))
            .setParams(
                PrfBasedDeriverParams.newBuilder()
                    .setDerivedKeyTemplate(
                        KeyTemplate.newBuilder().setTypeUrl("non existent type url").build()))
            .build();
    assertThrows(GeneralSecurityException.class, () -> factory.createKey(keyFormat));
  }

  @Test
  public void getPrimitive() throws Exception {
    HkdfPrfKeyManager.register(true);
    AesGcmKeyManager.register(true);

    byte[] randomInput = Random.randBytes(20);

    HkdfPrfKey prfKey =
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(32)))
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build();
    PrfBasedDeriverKey key =
        PrfBasedDeriverKey.newBuilder()
            .setPrfKey(
                TestUtil.createKeyData(
                    prfKey, HkdfPrfKeyManager.staticKeyType(), KeyMaterialType.SYMMETRIC))
            .setParams(
                PrfBasedDeriverParams.newBuilder()
                    .setDerivedKeyTemplate(AeadKeyTemplates.AES256_GCM))
            .build();

    KeysetHandle managerHandle =
        manager.getPrimitive(key, KeysetDeriver.class).deriveKeyset(randomInput);
    Keyset managerKeyset = CleartextKeysetHandle.getKeyset(managerHandle);
    AesGcmKey managerKey =
        AesGcmKey.parseFrom(
            managerKeyset.getKey(0).getKeyData().getValue(),
            ExtensionRegistryLite.getEmptyRegistry());

    KeysetHandle directHandle =
        PrfBasedDeriver.create(key.getPrfKey(), key.getParams().getDerivedKeyTemplate())
            .deriveKeyset(randomInput);
    Keyset directKeyset = CleartextKeysetHandle.getKeyset(directHandle);
    AesGcmKey directKey =
        AesGcmKey.parseFrom(
            directKeyset.getKey(0).getKeyData().getValue(),
            ExtensionRegistryLite.getEmptyRegistry());

    assertThat(managerKey.getKeyValue()).hasSize(32);
    assertThat(directKey.getKeyValue()).isEqualTo(managerKey.getKeyValue());
  }
}
