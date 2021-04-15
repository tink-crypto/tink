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
import static com.google.crypto.tink.testing.KeyTypeManagerTestUtil.testKeyTemplateCompatible;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacPrfKey;
import com.google.crypto.tink.proto.HmacPrfKeyFormat;
import com.google.crypto.tink.proto.HmacPrfParams;
import com.google.crypto.tink.subtle.PrfHmacJce;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link HmacPrfKeyManager}. */
@RunWith(JUnit4.class)
public class HmacPrfKeyManagerTest {
  private final HmacPrfKeyManager manager = new HmacPrfKeyManager();
  private final KeyTypeManager.KeyFactory<HmacPrfKeyFormat, HmacPrfKey> factory =
      manager.keyFactory();

  @Test
  public void validateKeyFormat_empty() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(HmacPrfKeyFormat.getDefaultInstance()));
  }

  private static HmacPrfKeyFormat makeHmacPrfKeyFormat(int keySize, HashType hashType) {
    HmacPrfParams params = HmacPrfParams.newBuilder().setHash(hashType).build();
    return HmacPrfKeyFormat.newBuilder().setParams(params).setKeySize(keySize).build();
  }

  @Test
  public void validateKeyFormat_keySizes() throws Exception {
    factory.validateKeyFormat(makeHmacPrfKeyFormat(16, HashType.SHA256));
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(makeHmacPrfKeyFormat(15, HashType.SHA256)));
  }

  @Test
  public void createKey_valid() throws Exception {
    manager.validateKey(factory.createKey(makeHmacPrfKeyFormat(16, HashType.SHA1)));
    manager.validateKey(factory.createKey(makeHmacPrfKeyFormat(20, HashType.SHA1)));
    manager.validateKey(factory.createKey(makeHmacPrfKeyFormat(32, HashType.SHA1)));
    manager.validateKey(factory.createKey(makeHmacPrfKeyFormat(16, HashType.SHA256)));
    manager.validateKey(factory.createKey(makeHmacPrfKeyFormat(32, HashType.SHA256)));
    manager.validateKey(factory.createKey(makeHmacPrfKeyFormat(16, HashType.SHA512)));
    manager.validateKey(factory.createKey(makeHmacPrfKeyFormat(32, HashType.SHA512)));
    manager.validateKey(factory.createKey(makeHmacPrfKeyFormat(64, HashType.SHA512)));
  }

  @Test
  public void createKey_checkValues() throws Exception {
    HmacPrfKeyFormat keyFormat = makeHmacPrfKeyFormat(16, HashType.SHA256);
    HmacPrfKey key = factory.createKey(keyFormat);
    assertThat(key.getKeyValue()).hasSize(keyFormat.getKeySize());
    assertThat(key.getParams().getHash()).isEqualTo(keyFormat.getParams().getHash());
  }

  @Test
  public void createKey_multipleTimes() throws Exception {
    HmacPrfKeyFormat keyFormat = makeHmacPrfKeyFormat(16, HashType.SHA256);
    int numKeys = 100;
    Set<String> keys = new TreeSet<String>();
    for (int i = 0; i < numKeys; ++i) {
      keys.add(TestUtil.hexEncode(factory.createKey(keyFormat).getKeyValue().toByteArray()));
    }
    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void validateKey_wrongVersion_throws() throws Exception {
    HmacPrfKey validKey = factory.createKey(makeHmacPrfKeyFormat(16, HashType.SHA1));
    assertThrows(
        GeneralSecurityException.class,
        () -> manager.validateKey(HmacPrfKey.newBuilder(validKey).setVersion(1).build()));
  }

  @Test
  public void validateKey_notValid_throws() throws Exception {
    HmacPrfKey validKey = factory.createKey(makeHmacPrfKeyFormat(16, HashType.SHA1));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            manager.validateKey(
                HmacPrfKey.newBuilder(validKey)
                    .setKeyValue(ByteString.copyFrom(Random.randBytes(15)))
                    .build()));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            manager.validateKey(
                HmacPrfKey.newBuilder(validKey)
                    .setParams(
                        HmacPrfParams.newBuilder(validKey.getParams())
                            .setHash(HashType.UNKNOWN_HASH)
                            .build())
                    .build()));
  }

  @Test
  public void getPrimitive_worksForSha1() throws Exception {
    HmacPrfKey validKey = factory.createKey(makeHmacPrfKeyFormat(16, HashType.SHA1));
    Prf managerPrf = manager.getPrimitive(validKey, Prf.class);
    Prf directPrf =
        new PrfHmacJce("HMACSHA1", new SecretKeySpec(validKey.getKeyValue().toByteArray(), "HMAC"));
    byte[] message = Random.randBytes(50);
    assertThat(managerPrf.compute(message, 19)).isEqualTo(directPrf.compute(message, 19));
  }

  @Test
  public void getPrimitive_worksForSha256() throws Exception {
    HmacPrfKey validKey = factory.createKey(makeHmacPrfKeyFormat(16, HashType.SHA256));
    Prf managerPrf = manager.getPrimitive(validKey, Prf.class);
    Prf directPrf =
        new PrfHmacJce(
            "HMACSHA256", new SecretKeySpec(validKey.getKeyValue().toByteArray(), "HMAC"));
    byte[] message = Random.randBytes(50);
    assertThat(managerPrf.compute(message, 29)).isEqualTo(directPrf.compute(message, 29));
  }

  @Test
  public void getPrimitive_worksForSha512() throws Exception {
    HmacPrfKey validKey = factory.createKey(makeHmacPrfKeyFormat(16, HashType.SHA512));
    Prf managerPrf = manager.getPrimitive(validKey, Prf.class);
    Prf directPrf =
        new PrfHmacJce(
            "HMACSHA512", new SecretKeySpec(validKey.getKeyValue().toByteArray(), "HMAC"));
    byte[] message = Random.randBytes(50);
    assertThat(managerPrf.compute(message, 33)).isEqualTo(directPrf.compute(message, 33));
  }

  @Test
  public void testDeriveKey_size27() throws Exception {
    final int keySize = 27;

    byte[] keyMaterial = Random.randBytes(100);
    HmacPrfParams params = HmacPrfParams.newBuilder().setHash(HashType.SHA256).build();
    HmacPrfKey key =
        factory.deriveKey(
            HmacPrfKeyFormat.newBuilder()
                .setVersion(0)
                .setParams(params)
                .setKeySize(keySize)
                .build(),
            new ByteArrayInputStream(keyMaterial));
    assertThat(key.getKeyValue()).hasSize(keySize);
    for (int i = 0; i < keySize; ++i) {
      assertThat(key.getKeyValue().byteAt(i)).isEqualTo(keyMaterial[i]);
    }
    assertThat(key.getParams()).isEqualTo(params);
  }

  @Test
  public void testDeriveKey_notEnoughKeyMaterial_throws() throws Exception {
    byte[] keyMaterial = Random.randBytes(31);
    HmacPrfParams params = HmacPrfParams.newBuilder().setHash(HashType.SHA256).build();
    HmacPrfKeyFormat format =
        HmacPrfKeyFormat.newBuilder().setVersion(0).setParams(params).setKeySize(32).build();
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.deriveKey(format, new ByteArrayInputStream(keyMaterial)));
  }

  @Test
  public void testDeriveKey_badVersion_throws() throws Exception {
    final int keySize = 32;

    byte[] keyMaterial = Random.randBytes(100);
    HmacPrfParams params = HmacPrfParams.newBuilder().setHash(HashType.SHA256).build();
    HmacPrfKeyFormat format =
        HmacPrfKeyFormat.newBuilder().setVersion(1).setParams(params).setKeySize(keySize).build();
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.deriveKey(format, new ByteArrayInputStream(keyMaterial)));
  }

  @Test
  public void testDeriveKey_justEnoughKeyMaterial() throws Exception {
    final int keySize = 32;

    byte[] keyMaterial = Random.randBytes(keySize);
    HmacPrfParams params = HmacPrfParams.newBuilder().setHash(HashType.SHA256).build();
    HmacPrfKey key =
        factory.deriveKey(
            HmacPrfKeyFormat.newBuilder()
                .setVersion(0)
                .setParams(params)
                .setKeySize(keySize)
                .build(),
            new ByteArrayInputStream(keyMaterial));
    assertThat(key.getKeyValue()).hasSize(keySize);
    for (int i = 0; i < keySize; ++i) {
      assertThat(key.getKeyValue().byteAt(i)).isEqualTo(keyMaterial[i]);
    }
  }

  @Test
  public void testHmacSha256Template() throws Exception {
    KeyTemplate template = HmacPrfKeyManager.hmacSha256Template();
    assertThat(template.getTypeUrl()).isEqualTo(new HmacPrfKeyManager().getKeyType());
    assertThat(template.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.RAW);
    HmacPrfKeyFormat format =
        HmacPrfKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertThat(format.getKeySize()).isEqualTo(32);
    assertThat(format.getParams().getHash()).isEqualTo(HashType.SHA256);
  }

  @Test
  public void testHmacSha512Template() throws Exception {
    KeyTemplate template = HmacPrfKeyManager.hmacSha512Template();
    assertThat(template.getTypeUrl()).isEqualTo(new HmacPrfKeyManager().getKeyType());
    assertThat(template.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.RAW);
    HmacPrfKeyFormat format =
        HmacPrfKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertThat(format.getKeySize()).isEqualTo(64);
    assertThat(format.getParams().getHash()).isEqualTo(HashType.SHA512);
  }

  @Test
  public void testKeyTemplateAndManagerCompatibility() throws Exception {
    HmacPrfKeyManager manager = new HmacPrfKeyManager();

    testKeyTemplateCompatible(manager, HmacPrfKeyManager.hmacSha256Template());
    testKeyTemplateCompatible(manager, HmacPrfKeyManager.hmacSha512Template());
  }

  @Test
  public void testKeyFormats() throws Exception {
    factory.validateKeyFormat(factory.keyFormats().get("HMAC_SHA256_PRF").keyFormat);
    factory.validateKeyFormat(factory.keyFormats().get("HMAC_SHA512_PRF").keyFormat);
  }
}
