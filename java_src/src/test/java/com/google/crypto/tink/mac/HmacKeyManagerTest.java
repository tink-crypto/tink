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
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.HmacKeyFormat;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.PrfHmacJce;
import com.google.crypto.tink.subtle.PrfMac;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link HmacKeyManager}. */
@RunWith(Theories.class)
public class HmacKeyManagerTest {
  private final HmacKeyManager manager = new HmacKeyManager();
  private final KeyTypeManager.KeyFactory<HmacKeyFormat, HmacKey> factory = manager.keyFactory();

  @Before
  public void register() throws Exception {
    MacConfig.register();
  }

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
      keys.add(Hex.encode(factory.createKey(keyFormat).getKeyValue().toByteArray()));
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
            manager,
            HmacKeyFormat.newBuilder().setVersion(0).setParams(params).setKeySize(keySize).build(),
            new ByteArrayInputStream(keyMaterial));
    assertThat(key.getKeyValue()).hasSize(keySize);
    for (int i = 0; i < keySize; ++i) {
      assertThat(key.getKeyValue().byteAt(i)).isEqualTo(keyMaterial[i]);
    }
    assertThat(key.getParams()).isEqualTo(params);
  }

  @Test
  public void testDeriveKey_handlesDataFragmentationCorrectly() throws Exception {
    int keySize = 32;
    byte randomness = 4;
    InputStream fragmentedInputStream =
        new InputStream() {
          @Override
          public int read() {
            return 0;
          }

          @Override
          public int read(byte[] b, int off, int len) {
            b[off] = randomness;
            return 1;
          }
        };

    HmacParams params = HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(32).build();
    HmacKey key =
        factory.deriveKey(
            manager,
            HmacKeyFormat.newBuilder().setVersion(0).setParams(params).setKeySize(keySize).build(),
            fragmentedInputStream);

    assertThat(key.getKeyValue()).hasSize(keySize);
    for (int i = 0; i < keySize; ++i) {
      assertThat(key.getKeyValue().byteAt(i)).isEqualTo(randomness);
    }
  }

  @Test
  public void testDeriveKey_notEnoughKeyMaterial_throws() throws Exception {
    byte[] keyMaterial = Random.randBytes(31);
    HmacParams params = HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(32).build();
    HmacKeyFormat format =
        HmacKeyFormat.newBuilder().setVersion(0).setParams(params).setKeySize(32).build();
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.deriveKey(manager, format, new ByteArrayInputStream(keyMaterial)));
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
        () -> factory.deriveKey(manager, format, new ByteArrayInputStream(keyMaterial)));
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
            manager,
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
    assertThat(template.toParameters())
        .isEqualTo(
            HmacParameters.builder()
                .setKeySizeBytes(32)
                .setTagSizeBytes(16)
                .setHashType(HmacParameters.HashType.SHA256)
                .setVariant(HmacParameters.Variant.TINK)
                .build());
  }

  @Test
  public void testHmacSha256Template() throws Exception {
    KeyTemplate template = HmacKeyManager.hmacSha256Template();
    assertThat(template.toParameters())
        .isEqualTo(
            HmacParameters.builder()
                .setKeySizeBytes(32)
                .setTagSizeBytes(32)
                .setHashType(HmacParameters.HashType.SHA256)
                .setVariant(HmacParameters.Variant.TINK)
                .build());
  }

  @Test
  public void testHmacSha512HalfDigestTemplate() throws Exception {
    KeyTemplate template = HmacKeyManager.hmacSha512HalfDigestTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            HmacParameters.builder()
                .setKeySizeBytes(64)
                .setTagSizeBytes(32)
                .setHashType(HmacParameters.HashType.SHA512)
                .setVariant(HmacParameters.Variant.TINK)
                .build());
  }

  @Test
  public void testHmacSha512Template() throws Exception {
    KeyTemplate template = HmacKeyManager.hmacSha512Template();
    assertThat(template.toParameters())
        .isEqualTo(
            HmacParameters.builder()
                .setKeySizeBytes(64)
                .setTagSizeBytes(64)
                .setHashType(HmacParameters.HashType.SHA512)
                .setVariant(HmacParameters.Variant.TINK)
                .build());
  }

  @Test
  public void testKeyTemplatesWork() throws Exception {
    Parameters p = HmacKeyManager.hmacSha256Template().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p = HmacKeyManager.hmacSha256HalfDigestTemplate().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p = HmacKeyManager.hmacSha512Template().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p = HmacKeyManager.hmacSha512HalfDigestTemplate().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @DataPoints("templateNames")
  public static final String[] KEY_TEMPLATES =
      new String[] {
        "HMAC_SHA256_128BITTAG",
        "HMAC_SHA256_128BITTAG_RAW",
        "HMAC_SHA256_256BITTAG",
        "HMAC_SHA256_256BITTAG_RAW",
        "HMAC_SHA512_128BITTAG",
        "HMAC_SHA512_128BITTAG_RAW",
        "HMAC_SHA512_256BITTAG",
        "HMAC_SHA512_256BITTAG_RAW",
        "HMAC_SHA512_512BITTAG",
        "HMAC_SHA512_512BITTAG_RAW"
      };

  @Theory
  public void testTemplates(@FromDataPoints("templateNames") String templateName) throws Exception {
    KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters())
        .isEqualTo(KeyTemplates.get(templateName).toParameters());
  }

  @Theory
  public void testCreateKeyFromRandomness(@FromDataPoints("templateNames") String templateName)
      throws Exception {
    byte[] keyMaterial =
        new byte[] {
          0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
          25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
          47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68,
        };
    HmacParameters parameters = (HmacParameters) KeyTemplates.get(templateName).toParameters();
    com.google.crypto.tink.mac.HmacKey key =
        HmacKeyManager.createHmacKeyFromRandomness(
            parameters,
            new ByteArrayInputStream(keyMaterial),
            parameters.hasIdRequirement() ? 123 : null,
            InsecureSecretKeyAccess.get());
    byte[] expectedKeyBytes = Arrays.copyOf(keyMaterial, parameters.getKeySizeBytes());
    Key expectedKey =
        com.google.crypto.tink.mac.HmacKey.builder()
            .setParameters(parameters)
            .setIdRequirement(parameters.hasIdRequirement() ? 123 : null)
            .setKeyBytes(SecretBytes.copyFrom(expectedKeyBytes, InsecureSecretKeyAccess.get()))
            .build();
    assertTrue(key.equalsKey(expectedKey));
  }
}
