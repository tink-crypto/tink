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

package com.google.crypto.tink.mac;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.SlowInputStream;
import com.google.crypto.tink.mac.internal.HmacTestUtil;
import com.google.crypto.tink.mac.internal.HmacTestUtil.HmacTestVector;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBytes;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;
import javax.annotation.Nullable;
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
  @Before
  public void register() throws Exception {
    MacConfig.register();
  }

  @Test
  public void testKeyManagerRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager("type.googleapis.com/google.crypto.tink.HmacKey", Mac.class))
        .isNotNull();
  }

  @Test
  public void createKey_multipleTimes() throws Exception {
    HmacParameters parameters =
        HmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(16)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.TINK)
            .build();
    int numKeys = 100;
    Set<String> keys = new TreeSet<>();
    for (int i = 0; i < numKeys; ++i) {
      KeysetHandle handle = KeysetHandle.generateNew(parameters);
      com.google.crypto.tink.mac.HmacKey macKey =
          (com.google.crypto.tink.mac.HmacKey) handle.getAt(0).getKey();
      keys.add(Hex.encode(macKey.getKeyBytes().toByteArray(InsecureSecretKeyAccess.get())));
    }
    assertThat(keys).hasSize(numKeys);
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

  @Test
  public void testCreateKeyFromRandomness_slowInputStream_works() throws Exception {
    byte[] keyMaterial =
        new byte[] {
          0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
          25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
          47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68,
        };
    HmacParameters parameters =
        HmacParameters.builder()
            .setKeySizeBytes(64)
            .setTagSizeBytes(64)
            .setHashType(HmacParameters.HashType.SHA512)
            .setVariant(HmacParameters.Variant.TINK)
            .build();
    com.google.crypto.tink.mac.HmacKey key =
        HmacKeyManager.createHmacKeyFromRandomness(
            parameters, SlowInputStream.copyFrom(keyMaterial), 7975, InsecureSecretKeyAccess.get());
    byte[] expectedKeyBytes = Arrays.copyOf(keyMaterial, parameters.getKeySizeBytes());
    Key expectedKey =
        com.google.crypto.tink.mac.HmacKey.builder()
            .setParameters(parameters)
            .setIdRequirement(7975)
            .setKeyBytes(SecretBytes.copyFrom(expectedKeyBytes, InsecureSecretKeyAccess.get()))
            .build();
    assertTrue(key.equalsKey(expectedKey));
  }

  @DataPoints("hmacTestVectors")
  public static final HmacTestVector[] HMAC_TEST_VECTORS = HmacTestUtil.HMAC_TEST_VECTORS;

  @Theory
  public void testGetPrimitive_chunkedMac_works(@FromDataPoints("hmacTestVectors") HmacTestVector t)
      throws Exception {
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(t.key).makePrimary();
    @Nullable Integer id = t.key.getIdRequirementOrNull();
    if (id == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(id);
    }
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
    ChunkedMac chunkedMac = handle.getPrimitive(ChunkedMac.class);

    ChunkedMacComputation chunkedMacComputation = chunkedMac.createComputation();
    chunkedMacComputation.update(ByteBuffer.wrap(t.message).asReadOnlyBuffer());
    assertThat(t.tag).isEqualTo(chunkedMacComputation.computeMac());

    ChunkedMacVerification chunkedHmacVerification = chunkedMac.createVerification(t.tag);
    chunkedHmacVerification.update(ByteBuffer.wrap(t.message));
    chunkedHmacVerification.verifyMac();
  }

  @Theory
  public void testGetPrimitive_mac_works(@FromDataPoints("hmacTestVectors") HmacTestVector t)
      throws Exception {
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(t.key).makePrimary();
    @Nullable Integer id = t.key.getIdRequirementOrNull();
    if (id == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(id);
    }
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
    Mac mac = handle.getPrimitive(Mac.class);

    assertThat(t.tag).isEqualTo(mac.computeMac(t.message));
    mac.verifyMac(t.tag, t.message);
  }

  @Test
  public void testSerializeAndParse_works() throws Exception {
    HmacParameters parameters =
        HmacParameters.builder()
            .setKeySizeBytes(64)
            .setTagSizeBytes(64)
            .setHashType(HmacParameters.HashType.SHA512)
            .setVariant(HmacParameters.Variant.TINK)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    byte[] serialized =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serialized, InsecureSecretKeyAccess.get());

    assertTrue(handle.equalsKeyset(parsed));
  }
}
