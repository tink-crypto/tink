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

package com.google.crypto.tink.prf;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.proto.AesCmacPrfKey;
import com.google.crypto.tink.proto.AesCmacPrfKeyFormat;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.PrfAesCmac;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Test for AesCmacPrfKeyManager. */
@RunWith(Theories.class)
public class AesCmacPrfKeyManagerTest {

  @Before
  public void register() throws Exception {
    PrfConfig.register();
  }

  @Test
  public void validateKeyFormat_empty() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            new AesCmacPrfKeyManager()
                .keyFactory()
                .validateKeyFormat(AesCmacPrfKeyFormat.getDefaultInstance()));
  }

  private static AesCmacPrfKeyFormat makeAesCmacPrfKeyFormat(int keySize) {
    return AesCmacPrfKeyFormat.newBuilder().setKeySize(keySize).build();
  }

  @Test
  public void validateKeyFormat_valid() throws Exception {
    AesCmacPrfKeyManager manager = new AesCmacPrfKeyManager();
    manager.keyFactory().validateKeyFormat(makeAesCmacPrfKeyFormat(32));
  }

  @Test
  public void validateKeyFormat_notValid_throws() throws Exception {
    AesCmacPrfKeyManager manager = new AesCmacPrfKeyManager();
    assertThrows(
        GeneralSecurityException.class,
        () -> manager.keyFactory().validateKeyFormat(makeAesCmacPrfKeyFormat(31)));
    assertThrows(
        GeneralSecurityException.class,
        () -> manager.keyFactory().validateKeyFormat(makeAesCmacPrfKeyFormat(16)));
  }

  @Test
  public void createKey_valid() throws Exception {
    AesCmacPrfKeyManager manager = new AesCmacPrfKeyManager();
    manager.validateKey(manager.keyFactory().createKey(makeAesCmacPrfKeyFormat(32)));
  }

  @Test
  public void createKey_checkValues() throws Exception {
    AesCmacPrfKeyFormat keyFormat = makeAesCmacPrfKeyFormat(32);
    AesCmacPrfKey key = new AesCmacPrfKeyManager().keyFactory().createKey(keyFormat);
    assertThat(key.getKeyValue()).hasSize(keyFormat.getKeySize());
  }

  @Test
  public void createKey_multipleTimes() throws Exception {
    AesCmacPrfKeyManager manager = new AesCmacPrfKeyManager();
    AesCmacPrfKeyFormat keyFormat = makeAesCmacPrfKeyFormat(32);
    assertThat(manager.keyFactory().createKey(keyFormat).getKeyValue())
        .isNotEqualTo(manager.keyFactory().createKey(keyFormat).getKeyValue());
  }

  @Test
  public void validateKey_valid() throws Exception {
    AesCmacPrfKeyManager manager = new AesCmacPrfKeyManager();
    manager.validateKey(manager.keyFactory().createKey(makeAesCmacPrfKeyFormat(32)));
  }

  @Test
  public void validateKey_wrongVersion_throws() throws Exception {
    AesCmacPrfKeyManager manager = new AesCmacPrfKeyManager();
    AesCmacPrfKey validKey = manager.keyFactory().createKey(makeAesCmacPrfKeyFormat(32));
    assertThrows(
        GeneralSecurityException.class,
        () -> manager.validateKey(AesCmacPrfKey.newBuilder(validKey).setVersion(1).build()));
  }

  @Test
  public void validateKey_notValid_throws() throws Exception {
    AesCmacPrfKeyManager manager = new AesCmacPrfKeyManager();
    AesCmacPrfKey validKey = manager.keyFactory().createKey(makeAesCmacPrfKeyFormat(32));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            manager.validateKey(
                AesCmacPrfKey.newBuilder(validKey)
                    .setKeyValue(ByteString.copyFrom(Random.randBytes(16)))
                    .build()));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            manager.validateKey(
                AesCmacPrfKey.newBuilder(validKey)
                    .setKeyValue(ByteString.copyFrom(Random.randBytes(64)))
                    .build()));
  }

  @Test
  public void getPrimitive_works() throws Exception {
    AesCmacPrfKeyManager manager = new AesCmacPrfKeyManager();
    AesCmacPrfKey validKey = manager.keyFactory().createKey(makeAesCmacPrfKeyFormat(32));
    Prf managerPrf = manager.getPrimitive(validKey, Prf.class);
    Prf directPrf = new PrfAesCmac(validKey.getKeyValue().toByteArray());
    byte[] message = Random.randBytes(50);
    assertThat(managerPrf.compute(message, 16)).isEqualTo(directPrf.compute(message, 16));
  }

  @Test
  public void testAes256CmacTemplate() throws Exception {
    KeyTemplate template = AesCmacPrfKeyManager.aes256CmacTemplate();
    assertThat(template.toParameters()).isEqualTo(AesCmacPrfParameters.create(32));
  }

  @Test
  public void testKeyTemplateAndManagerCompatibility() throws Exception {
    Parameters p = AesCmacPrfKeyManager.aes256CmacTemplate().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @DataPoints("templateNames")
  public static final String[] KEY_TEMPLATES =
      new String[] {
        "AES256_CMAC_PRF", "AES_CMAC_PRF",
      };

  @Theory
  public void testTemplates(@FromDataPoints("templateNames") String templateName) throws Exception {
    KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters())
        .isEqualTo(KeyTemplates.get(templateName).toParameters());
  }

  @Test
  public void registersPrfPrimitiveConstructor() throws Exception {
    Prf prf =
        MutablePrimitiveRegistry.globalInstance()
            .getPrimitive(
                com.google.crypto.tink.prf.AesCmacPrfKey.create(
                    AesCmacPrfParameters.create(32), SecretBytes.randomBytes(32)),
                Prf.class);

    assertThat(prf).isInstanceOf(PrfAesCmac.class);
  }

  @Test
  public void testKeyManagerRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager("type.googleapis.com/google.crypto.tink.AesCmacPrfKey", Prf.class))
        .isNotNull();
  }

  @Test
  public void createKey_works() throws Exception {
    AesCmacPrfParameters params = AesCmacPrfParameters.create(32);
    KeysetHandle handle = KeysetHandle.generateNew(params);
    assertThat(handle.size()).isEqualTo(1);
    com.google.crypto.tink.prf.AesCmacPrfKey key =
        (com.google.crypto.tink.prf.AesCmacPrfKey) handle.getAt(0).getKey();
    assertThat(key.getParameters()).isEqualTo(params);
  }

  @Test
  public void createKey_differentKeyValues_alwaysDifferent() throws Exception {
    AesCmacPrfParameters params = AesCmacPrfParameters.create(32);

    int numKeys = 100;
    Set<String> keys = new TreeSet<>();
    for (int i = 0; i < numKeys; i++) {
      KeysetHandle handle = KeysetHandle.generateNew(params);
      assertThat(handle.size()).isEqualTo(1);
      com.google.crypto.tink.prf.AesCmacPrfKey key =
          (com.google.crypto.tink.prf.AesCmacPrfKey) handle.getAt(0).getKey();
      keys.add(Hex.encode(key.getKeyBytes().toByteArray(InsecureSecretKeyAccess.get())));
    }
    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void createPrimitiveAndUseIt_works() throws Exception {
    AesCmacPrfParameters params = AesCmacPrfParameters.create(32);
    KeysetHandle handle = KeysetHandle.generateNew(params);
    assertThat(handle.size()).isEqualTo(1);
    PrfSet prfSet = handle.getPrimitive(PrfSet.class);
    Prf directPrf =
        PrfAesCmac.create((com.google.crypto.tink.prf.AesCmacPrfKey) handle.getAt(0).getKey());
    assertThat(prfSet.computePrimary(new byte[0], 16))
        .isEqualTo(directPrf.compute(new byte[0], 16));
  }

  @Test
  public void serializeAndDeserializeKeysets() throws Exception {
    AesCmacPrfParameters params = AesCmacPrfParameters.create(32);
    KeysetHandle handle = KeysetHandle.generateNew(params);

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());
    assertTrue(parsed.equalsKeyset(handle));
  }

  @Test
  public void createKeyWith16Bytes_throws() throws Exception {
    AesCmacPrfParameters params = AesCmacPrfParameters.create(16);
    assertThrows(GeneralSecurityException.class, () -> KeysetHandle.generateNew(params));
  }

  @Test
  public void createPrimitiveWith16Bytes_throws() throws Exception {
    AesCmacPrfParameters params = AesCmacPrfParameters.create(16);
    com.google.crypto.tink.prf.AesCmacPrfKey key =
        com.google.crypto.tink.prf.AesCmacPrfKey.create(params, SecretBytes.randomBytes(16));
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(1).makePrimary())
            .build();
    assertThrows(GeneralSecurityException.class, () -> handle.getPrimitive(PrfSet.class));
  }

  @Test
  public void serializeDeserializeKeysetsWith16Bytes_works() throws Exception {
    AesCmacPrfParameters params = AesCmacPrfParameters.create(16);
    com.google.crypto.tink.prf.AesCmacPrfKey key =
        com.google.crypto.tink.prf.AesCmacPrfKey.create(params, SecretBytes.randomBytes(16));
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(1).makePrimary())
            .build();
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());
    assertTrue(parsed.equalsKeyset(handle));
  }
}
