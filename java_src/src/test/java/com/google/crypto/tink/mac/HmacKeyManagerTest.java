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

package com.google.crypto.tink.mac;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.testing.KeyTypeManagerTestUtil.testKeyTemplateCompatible;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.HmacKeyFormat;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.subtle.PrfHmacJce;
import com.google.crypto.tink.subtle.PrfMac;
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

/** Unit tests for {@link HmacKeyManager}. */
@RunWith(JUnit4.class)
public class HmacKeyManagerTest {
  private final HmacKeyManager manager = new HmacKeyManager();
  private final KeyTypeManager.KeyFactory<HmacKeyFormat, HmacKey> factory = manager.keyFactory();

  @Test
  public void validateKeyFormat_empty() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(HmacKeyFormat.getDefaultInstance()));
  }

  private static HmacKeyFormat makeHmacKeyFormat(int keySize, int tagSize, HashType hashType) {
    HmacParams params = HmacParams.newBuilder()
        .setHash(hashType)
        .setTagSize(tagSize)
        .build();
    return HmacKeyFormat.newBuilder()
        .setParams(params)
        .setKeySize(keySize)
        .build();
  }

  @Test
  public void validateKeyFormat_tagSizesSha1() throws Exception {
    factory.validateKeyFormat(makeHmacKeyFormat(16, 10, HashType.SHA1));
    factory.validateKeyFormat(makeHmacKeyFormat(16, 11, HashType.SHA1));
    factory.validateKeyFormat(makeHmacKeyFormat(16, 12, HashType.SHA1));
    factory.validateKeyFormat(makeHmacKeyFormat(16, 13, HashType.SHA1));
    factory.validateKeyFormat(makeHmacKeyFormat(16, 14, HashType.SHA1));
    factory.validateKeyFormat(makeHmacKeyFormat(16, 15, HashType.SHA1));
    factory.validateKeyFormat(makeHmacKeyFormat(16, 16, HashType.SHA1));
    factory.validateKeyFormat(makeHmacKeyFormat(16, 17, HashType.SHA1));
    factory.validateKeyFormat(makeHmacKeyFormat(16, 18, HashType.SHA1));
    factory.validateKeyFormat(makeHmacKeyFormat(16, 19, HashType.SHA1));
    factory.validateKeyFormat(makeHmacKeyFormat(16, 20, HashType.SHA1));
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(makeHmacKeyFormat(16, 21, HashType.SHA1)));
  }

  @Test
  public void validateKeyFormat_tagSizesSha256() throws Exception {
    factory.validateKeyFormat(makeHmacKeyFormat(16, 10, HashType.SHA256));
    factory.validateKeyFormat(makeHmacKeyFormat(16, 11, HashType.SHA256));
    factory.validateKeyFormat(makeHmacKeyFormat(16, 12, HashType.SHA256));

    factory.validateKeyFormat(makeHmacKeyFormat(16, 30, HashType.SHA256));
    factory.validateKeyFormat(makeHmacKeyFormat(16, 31, HashType.SHA256));
    factory.validateKeyFormat(makeHmacKeyFormat(16, 32, HashType.SHA256));
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(makeHmacKeyFormat(16, 33, HashType.SHA256)));
  }

  @Test
  public void validateKeyFormat_tagSizesSha512() throws Exception {
    factory.validateKeyFormat(makeHmacKeyFormat(16, 10, HashType.SHA512));
    factory.validateKeyFormat(makeHmacKeyFormat(16, 11, HashType.SHA512));
    factory.validateKeyFormat(makeHmacKeyFormat(16, 12, HashType.SHA512));

    factory.validateKeyFormat(makeHmacKeyFormat(16, 62, HashType.SHA512));
    factory.validateKeyFormat(makeHmacKeyFormat(16, 63, HashType.SHA512));
    factory.validateKeyFormat(makeHmacKeyFormat(16, 64, HashType.SHA512));
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(makeHmacKeyFormat(16, 65, HashType.SHA512)));
  }

  @Test
  public void validateKeyFormat_keySizes() throws Exception {
    factory.validateKeyFormat(makeHmacKeyFormat(16, 10, HashType.SHA256));
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(makeHmacKeyFormat(15, 10, HashType.SHA256)));
  }

  @Test
  public void createKey_valid() throws Exception {
    manager.validateKey(factory.createKey(makeHmacKeyFormat(16, 10, HashType.SHA1)));
    manager.validateKey(factory.createKey(makeHmacKeyFormat(16, 20, HashType.SHA1)));
    manager.validateKey(factory.createKey(makeHmacKeyFormat(16, 10, HashType.SHA256)));
    manager.validateKey(factory.createKey(makeHmacKeyFormat(16, 32, HashType.SHA256)));
    manager.validateKey(factory.createKey(makeHmacKeyFormat(16, 10, HashType.SHA512)));
    manager.validateKey(factory.createKey(makeHmacKeyFormat(16, 64, HashType.SHA512)));
  }

  @Test
  public void createKey_checkValues() throws Exception {
    HmacKeyFormat keyFormat = makeHmacKeyFormat(16, 10, HashType.SHA256);
    HmacKey key = factory.createKey(keyFormat);
    assertThat(key.getKeyValue()).hasSize(keyFormat.getKeySize());
    assertThat(key.getParams().getTagSize()).isEqualTo(keyFormat.getParams().getTagSize());
  }

  @Test
  public void createKey_multipleTimes() throws Exception {
    HmacKeyFormat keyFormat = makeHmacKeyFormat(16, 10, HashType.SHA256);
    int numKeys = 100;
    Set<String> keys = new TreeSet<>();
    for (int i = 0; i < numKeys; ++i) {
      keys.add(TestUtil.hexEncode(factory.createKey(keyFormat).getKeyValue().toByteArray()));
    }
    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void validateKey_wrongVersion_throws() throws Exception {
    HmacKey validKey = factory.createKey(makeHmacKeyFormat(16, 10, HashType.SHA1));
    assertThrows(
        GeneralSecurityException.class,
        () -> manager.validateKey(HmacKey.newBuilder(validKey).setVersion(1).build()));
  }

  @Test
  public void validateKey_notValid_throws() throws Exception {
    HmacKey validKey = factory.createKey(makeHmacKeyFormat(16, 10, HashType.SHA1));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            manager.validateKey(
                HmacKey.newBuilder(validKey)
                    .setKeyValue(ByteString.copyFrom(Random.randBytes(15)))
                    .build()));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            manager.validateKey(
                HmacKey.newBuilder(validKey)
                    .setParams(HmacParams.newBuilder(validKey.getParams()).setTagSize(0).build())
                    .build()));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            manager.validateKey(
                HmacKey.newBuilder(validKey)
                    .setParams(HmacParams.newBuilder(validKey.getParams()).setTagSize(9).build())
                    .build()));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            manager.validateKey(
                HmacKey.newBuilder(validKey)
                    .setParams(HmacParams.newBuilder(validKey.getParams()).setTagSize(21).build())
                    .build()));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            manager.validateKey(
                HmacKey.newBuilder(validKey)
                    .setParams(HmacParams.newBuilder(validKey.getParams()).setTagSize(32).build())
                    .build()));
  }

  @Test
  public void getPrimitive_worksForSha1() throws Exception {
    HmacKey validKey = factory.createKey(makeHmacKeyFormat(16, 19, HashType.SHA1));
    Mac managerMac = manager.getPrimitive(validKey, Mac.class);
    Mac directMac =
        new PrfMac(
            new PrfHmacJce(
                "HMACSHA1", new SecretKeySpec(validKey.getKeyValue().toByteArray(), "HMAC")),
            19);
    byte[] message = Random.randBytes(50);
    managerMac.verifyMac(directMac.computeMac(message), message);
  }

  @Test
  public void getPrimitive_worksForSha256() throws Exception {
    HmacKey validKey = factory.createKey(makeHmacKeyFormat(16, 29, HashType.SHA256));
    Mac managerMac = manager.getPrimitive(validKey, Mac.class);
    Mac directMac =
        new PrfMac(
            new PrfHmacJce(
                "HMACSHA256", new SecretKeySpec(validKey.getKeyValue().toByteArray(), "HMAC")),
            29);
    byte[] message = Random.randBytes(50);
    managerMac.verifyMac(directMac.computeMac(message), message);
  }

  @Test
  public void getPrimitive_worksForSha512() throws Exception {
    HmacKey validKey = factory.createKey(makeHmacKeyFormat(16, 33, HashType.SHA512));
    Mac managerMac = manager.getPrimitive(validKey, Mac.class);
    Mac directMac =
        new PrfMac(
            new PrfHmacJce(
                "HMACSHA512", new SecretKeySpec(validKey.getKeyValue().toByteArray(), "HMAC")),
            33);
    byte[] message = Random.randBytes(50);
    managerMac.verifyMac(directMac.computeMac(message), message);
  }

  @Test
  public void testDeriveKey_size27() throws Exception {
    final int keySize = 27;

    byte[] keyMaterial = Random.randBytes(100);
    HmacParams params = HmacParams.newBuilder()
        .setHash(HashType.SHA256)
        .setTagSize(32)
        .build();
    HmacKey key =
        factory.deriveKey(
            HmacKeyFormat.newBuilder().setVersion(0).setParams(params).setKeySize(keySize).build(),
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
    HmacParams params = HmacParams.newBuilder()
        .setHash(HashType.SHA256)
        .setTagSize(32)
        .build();
    HmacKeyFormat format =
        HmacKeyFormat.newBuilder().setVersion(0).setParams(params).setKeySize(32).build();
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.deriveKey(format, new ByteArrayInputStream(keyMaterial)));
  }

  @Test
  public void testDeriveKey_badVersion_throws() throws Exception {
    final int keySize = 32;

    byte[] keyMaterial = Random.randBytes(100);
    HmacParams params = HmacParams.newBuilder()
        .setHash(HashType.SHA256)
        .setTagSize(32)
        .build();
    HmacKeyFormat format =
        HmacKeyFormat.newBuilder().setVersion(1).setParams(params).setKeySize(keySize).build();
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.deriveKey(format, new ByteArrayInputStream(keyMaterial)));
  }

  @Test
  public void testDeriveKey_justEnoughKeyMaterial() throws Exception {
    final int keySize = 32;

    byte[] keyMaterial = Random.randBytes(keySize);
    HmacParams params = HmacParams.newBuilder()
        .setHash(HashType.SHA256)
        .setTagSize(32)
        .build();
    HmacKey key =
        factory.deriveKey(
            HmacKeyFormat.newBuilder().setVersion(0).setParams(params).setKeySize(keySize).build(),
            new ByteArrayInputStream(keyMaterial));
    assertThat(key.getKeyValue()).hasSize(keySize);
    for (int i = 0; i < keySize; ++i) {
      assertThat(key.getKeyValue().byteAt(i)).isEqualTo(keyMaterial[i]);
    }
  }

  @Test
  public void testHmacSha256HalfDigestTemplate() throws Exception {
    KeyTemplate template = HmacKeyManager.hmacSha256HalfDigestTemplate();
    assertThat(template.getTypeUrl()).isEqualTo(new HmacKeyManager().getKeyType());
    assertThat(template.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.TINK);
    HmacKeyFormat format =
        HmacKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertThat(format.getKeySize()).isEqualTo(32);
    assertThat(format.getParams().getTagSize()).isEqualTo(16);
    assertThat(format.getParams().getHash()).isEqualTo(HashType.SHA256);
  }

  @Test
  public void testHmacSha256Template() throws Exception {
    KeyTemplate template = HmacKeyManager.hmacSha256Template();
    assertThat(template.getTypeUrl()).isEqualTo(new HmacKeyManager().getKeyType());
    assertThat(template.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.TINK);
    HmacKeyFormat format =
        HmacKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertThat(format.getKeySize()).isEqualTo(32);
    assertThat(format.getParams().getTagSize()).isEqualTo(32);
    assertThat(format.getParams().getHash()).isEqualTo(HashType.SHA256);
  }

  @Test
  public void testHmacSha512HalfDigestTemplate() throws Exception {
    KeyTemplate template = HmacKeyManager.hmacSha512HalfDigestTemplate();
    assertThat(template.getTypeUrl()).isEqualTo(new HmacKeyManager().getKeyType());
    assertThat(template.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.TINK);
    HmacKeyFormat format =
        HmacKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertThat(format.getKeySize()).isEqualTo(64);
    assertThat(format.getParams().getTagSize()).isEqualTo(32);
    assertThat(format.getParams().getHash()).isEqualTo(HashType.SHA512);
  }

  @Test
  public void testHmacSha512Template() throws Exception {
    KeyTemplate template = HmacKeyManager.hmacSha512Template();
    assertThat(template.getTypeUrl()).isEqualTo(new HmacKeyManager().getKeyType());
    assertThat(template.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.TINK);
    HmacKeyFormat format =
        HmacKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertThat(format.getKeySize()).isEqualTo(64);
    assertThat(format.getParams().getTagSize()).isEqualTo(64);
    assertThat(format.getParams().getHash()).isEqualTo(HashType.SHA512);
  }

  @Test
  public void testKeyTemplateAndManagerCompatibility() throws Exception {
    HmacKeyManager manager = new HmacKeyManager();

    testKeyTemplateCompatible(manager, HmacKeyManager.hmacSha256Template());
    testKeyTemplateCompatible(manager, HmacKeyManager.hmacSha256HalfDigestTemplate());
    testKeyTemplateCompatible(manager, HmacKeyManager.hmacSha512Template());
    testKeyTemplateCompatible(manager, HmacKeyManager.hmacSha512HalfDigestTemplate());
  }

  @Test
  public void testKeyFormats() throws Exception {
    factory.validateKeyFormat(factory.keyFormats().get("HMAC_SHA256_128BITTAG").keyFormat);
    factory.validateKeyFormat(factory.keyFormats().get("HMAC_SHA256_128BITTAG_RAW").keyFormat);

    factory.validateKeyFormat(factory.keyFormats().get("HMAC_SHA256_256BITTAG").keyFormat);
    factory.validateKeyFormat(factory.keyFormats().get("HMAC_SHA256_256BITTAG_RAW").keyFormat);

    factory.validateKeyFormat(factory.keyFormats().get("HMAC_SHA512_128BITTAG").keyFormat);
    factory.validateKeyFormat(factory.keyFormats().get("HMAC_SHA512_128BITTAG_RAW").keyFormat);

    factory.validateKeyFormat(factory.keyFormats().get("HMAC_SHA512_256BITTAG").keyFormat);
    factory.validateKeyFormat(factory.keyFormats().get("HMAC_SHA512_256BITTAG_RAW").keyFormat);

    factory.validateKeyFormat(factory.keyFormats().get("HMAC_SHA512_512BITTAG").keyFormat);
    factory.validateKeyFormat(factory.keyFormats().get("HMAC_SHA512_512BITTAG_RAW").keyFormat);
  }
}
