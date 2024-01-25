// Copyright 2017 Google LLC
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
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.PrfAesCmac;
import com.google.crypto.tink.util.SecretBytes;
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
    AesCmacPrfKey key = (AesCmacPrfKey) handle.getAt(0).getKey();
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
      AesCmacPrfKey key = (AesCmacPrfKey) handle.getAt(0).getKey();
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
    Prf directPrf = PrfAesCmac.create((AesCmacPrfKey) handle.getAt(0).getKey());
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
    AesCmacPrfKey key = AesCmacPrfKey.create(params, SecretBytes.randomBytes(16));
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(1).makePrimary())
            .build();
    assertThrows(GeneralSecurityException.class, () -> handle.getPrimitive(PrfSet.class));
  }

  @Test
  public void serializeDeserializeKeysetsWith16Bytes_works() throws Exception {
    AesCmacPrfParameters params = AesCmacPrfParameters.create(16);
    AesCmacPrfKey key = AesCmacPrfKey.create(params, SecretBytes.randomBytes(16));
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
