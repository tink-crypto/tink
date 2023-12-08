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

package com.google.crypto.tink.aead;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.internal.SlowInputStream;
import com.google.crypto.tink.proto.AesGcmKey;
import com.google.crypto.tink.proto.AesGcmKeyFormat;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Test for AesGcmJce and its key manager. */
@RunWith(Theories.class)
public class AesGcmKeyManagerTest {
  private final AesGcmKeyManager manager = new AesGcmKeyManager();
  private final KeyTypeManager.KeyFactory<AesGcmKeyFormat, AesGcmKey> factory =
      manager.keyFactory();

  @Before
  public void register() throws Exception {
    AeadConfig.register();
  }

  @Test
  public void basics() throws Exception {
    assertThat(manager.getKeyType()).isEqualTo("type.googleapis.com/google.crypto.tink.AesGcmKey");
    assertThat(manager.getVersion()).isEqualTo(0);
    assertThat(manager.keyMaterialType()).isEqualTo(KeyMaterialType.SYMMETRIC);
  }

  @Test
  public void validateKeyFormat_empty() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(AesGcmKeyFormat.getDefaultInstance()));
  }

  @Test
  public void validateKeyFormat_valid() throws Exception {
    factory.validateKeyFormat(AesGcmKeyFormat.newBuilder().setKeySize(16).build());
    factory.validateKeyFormat(AesGcmKeyFormat.newBuilder().setKeySize(32).build());
  }

  @Test
  public void validateKeyFormat_invalid() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(AesGcmKeyFormat.newBuilder().setKeySize(1).build()));
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(AesGcmKeyFormat.newBuilder().setKeySize(15).build()));
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(AesGcmKeyFormat.newBuilder().setKeySize(17).build()));
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(AesGcmKeyFormat.newBuilder().setKeySize(31).build()));
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(AesGcmKeyFormat.newBuilder().setKeySize(33).build()));
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(AesGcmKeyFormat.newBuilder().setKeySize(64).build()));
  }

  @Test
  public void createKey_16Bytes() throws Exception {
    AesGcmKey key = factory.createKey(AesGcmKeyFormat.newBuilder().setKeySize(16).build());
    assertThat(key.getKeyValue()).hasSize(16);
  }

  @Test
  public void createKey_32Bytes() throws Exception {
    AesGcmKey key = factory.createKey(AesGcmKeyFormat.newBuilder().setKeySize(32).build());
    assertThat(key.getKeyValue()).hasSize(32);
  }

  @Test
  public void createKey_multipleTimes() throws Exception {
    AesGcmKeyFormat format = AesGcmKeyFormat.newBuilder().setKeySize(16).build();
    Set<String> keys = new TreeSet<>();
    // Calls newKey multiple times and make sure that they generate different keys.
    int numTests = 50;
    for (int i = 0; i < numTests; i++) {
      keys.add(Hex.encode(factory.createKey(format).getKeyValue().toByteArray()));
    }
    assertThat(keys).hasSize(numTests);
  }

  @Test
  public void getPrimitive() throws Exception {
    AesGcmKey key = factory.createKey(AesGcmKeyFormat.newBuilder().setKeySize(16).build());
    Aead managerAead = manager.getPrimitive(key, Aead.class);
    Aead directAead = new AesGcmJce(key.getKeyValue().toByteArray());

    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    assertThat(directAead.decrypt(managerAead.encrypt(plaintext, associatedData), associatedData))
        .isEqualTo(plaintext);
  }

  private static class NistTestVector {
    String name;
    public byte[] keyValue;
    public byte[] plaintext;
    public byte[] aad;
    public byte[] iv;
    public byte[] ciphertext;
    public byte[] tag;

    public NistTestVector(
        String name,
        String keyValue,
        String plaintext,
        String aad,
        String iv,
        String ciphertext,
        String tag) {
      try {
        this.name = name;
        this.keyValue = Hex.decode(keyValue);
        this.plaintext = Hex.decode(plaintext);
        this.aad = Hex.decode(aad);
        this.iv = Hex.decode(iv);
        this.ciphertext = Hex.decode(ciphertext);
        this.tag = Hex.decode(tag);
      } catch (Exception ignored) {
        // Ignored
      }
    }
  }

  // Test vectors from
  // http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf.
  NistTestVector[] nistTestVectors = {
    new NistTestVector(
        "Test Case 1",
        "00000000000000000000000000000000",
        "",
        "",
        "000000000000000000000000",
        "",
        "58e2fccefa7e3061367f1d57a4e7455a"),
    new NistTestVector(
        "Test Case 2",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "",
        "000000000000000000000000",
        "0388dace60b6a392f328c2b971b2fe78",
        "ab6e47d42cec13bdf53a67b21257bddf"),
    new NistTestVector(
        "Test Case 3",
        "feffe9928665731c6d6a8f9467308308",
        "d9313225f88406e5a55909c5aff5269a"
            + "86a7a9531534f7da2e4c303d8a318a72"
            + "1c3c0c95956809532fcf0e2449a6b525"
            + "b16aedf5aa0de657ba637b391aafd255",
        "",
        "cafebabefacedbaddecaf888",
        "42831ec2217774244b7221b784d0d49c"
            + "e3aa212f2c02a4e035c17e2329aca12e"
            + "21d514b25466931c7d8f6a5aac84aa05"
            + "1ba30b396a0aac973d58e091473f5985",
        "4d5c2af327cd64a62cf35abd2ba6fab4"),
    new NistTestVector(
        "Test Case 4",
        "feffe9928665731c6d6a8f9467308308",
        "d9313225f88406e5a55909c5aff5269a"
            + "86a7a9531534f7da2e4c303d8a318a72"
            + "1c3c0c95956809532fcf0e2449a6b525"
            + "b16aedf5aa0de657ba637b39",
        "feedfacedeadbeeffeedfacedeadbeef" + "abaddad2",
        "cafebabefacedbaddecaf888",
        "42831ec2217774244b7221b784d0d49c"
            + "e3aa212f2c02a4e035c17e2329aca12e"
            + "21d514b25466931c7d8f6a5aac84aa05"
            + "1ba30b396a0aac973d58e091",
        "5bc94fbc3221a5db94fae95ae7121a47"),
    new NistTestVector(
        "Test Case 5",
        "feffe9928665731c6d6a8f9467308308",
        "d9313225f88406e5a55909c5aff5269a"
            + "86a7a9531534f7da2e4c303d8a318a72"
            + "1c3c0c95956809532fcf0e2449a6b525"
            + "b16aedf5aa0de657ba637b39",
        "feedfacedeadbeeffeedfacedeadbeef" + "abaddad2",
        "cafebabefacedbad",
        "61353b4c2806934a777ff51fa22a4755"
            + "699b2a714fcdc6f83766e5f97b6c7423"
            + "73806900e49f24b22b097544d4896b42"
            + "4989b5e1ebac0f07c23f4598",
        "3612d2e79e3b0785561be14aaca2fccb"),
    new NistTestVector(
        "Test Case 6",
        "feffe9928665731c6d6a8f9467308308",
        "d9313225f88406e5a55909c5aff5269a"
            + "86a7a9531534f7da2e4c303d8a318a72"
            + "1c3c0c95956809532fcf0e2449a6b525"
            + "b16aedf5aa0de657ba637b39",
        "feedfacedeadbeeffeedfacedeadbeef" + "abaddad2",
        "9313225df88406e555909c5aff5269aa"
            + "6a7a9538534f7da1e4c303d2a318a728"
            + "c3c0c95156809539fcf0e2429a6b5254"
            + "16aedbf5a0de6a57a637b39b",
        "8ce24998625615b603a033aca13fb894"
            + "be9112a5c3a211a8ba262a3cca7e2ca7"
            + "01e4a9a4fba43c90ccdcb281d48c7c6f"
            + "d62875d2aca417034c34aee5",
        "619cc5aefffe0bfa462af43c1699d050"),
    new NistTestVector(
        "Test Case 13",
        "00000000000000000000000000000000" + "00000000000000000000000000000000",
        "",
        "",
        "000000000000000000000000",
        "",
        "530f8afbc74536b9a963b4f1c4cb738b"),
    new NistTestVector(
        "Test Case 14",
        "00000000000000000000000000000000" + "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "",
        "000000000000000000000000",
        "cea7403d4d606b6e074ec5d3baf39d18",
        "d0d1c8a799996bf0265b98b5d48ab919"),
    new NistTestVector(
        "Test Case 15",
        "feffe9928665731c6d6a8f9467308308" + "feffe9928665731c6d6a8f9467308308",
        "d9313225f88406e5a55909c5aff5269a"
            + "86a7a9531534f7da2e4c303d8a318a72"
            + "1c3c0c95956809532fcf0e2449a6b525"
            + "b16aedf5aa0de657ba637b391aafd255",
        "",
        "cafebabefacedbaddecaf888",
        "522dc1f099567d07f47f37a32a84427d"
            + "643a8cdcbfe5c0c97598a2bd2555d1aa"
            + "8cb08e48590dbb3da7b08b1056828838"
            + "c5f61e6393ba7a0abcc9f662898015ad",
        "b094dac5d93471bdec1a502270e3cc6c"),
    new NistTestVector(
        "Test Case 16",
        "feffe9928665731c6d6a8f9467308308" + "feffe9928665731c6d6a8f9467308308",
        "d9313225f88406e5a55909c5aff5269a"
            + "86a7a9531534f7da2e4c303d8a318a72"
            + "1c3c0c95956809532fcf0e2449a6b525"
            + "b16aedf5aa0de657ba637b39",
        "feedfacedeadbeeffeedfacedeadbeef" + "abaddad2",
        "cafebabefacedbaddecaf888",
        "522dc1f099567d07f47f37a32a84427d"
            + "643a8cdcbfe5c0c97598a2bd2555d1aa"
            + "8cb08e48590dbb3da7b08b1056828838"
            + "c5f61e6393ba7a0abcc9f662",
        "76fc6ece0f4e1768cddf8853bb2d551b"),
    new NistTestVector(
        "Test Case 17",
        "feffe9928665731c6d6a8f9467308308" + "feffe9928665731c6d6a8f9467308308",
        "d9313225f88406e5a55909c5aff5269a"
            + "86a7a9531534f7da2e4c303d8a318a72"
            + "1c3c0c95956809532fcf0e2449a6b525"
            + "b16aedf5aa0de657ba637b39",
        "feedfacedeadbeeffeedfacedeadbeef" + "abaddad2",
        "cafebabefacedbad",
        "c3762df1ca787d32ae47c13bf19844cb"
            + "af1ae14d0b976afac52ff7d79bba9de0"
            + "feb582d33934a4f0954cc2363bc73f78"
            + "62ac430e64abe499f47c9b1f",
        "3a337dbf46a792c45e454913fe2ea8f2"),
    new NistTestVector(
        "Test Case 18",
        "feffe9928665731c6d6a8f9467308308" + "feffe9928665731c6d6a8f9467308308",
        "d9313225f88406e5a55909c5aff5269a"
            + "86a7a9531534f7da2e4c303d8a318a72"
            + "1c3c0c95956809532fcf0e2449a6b525"
            + "b16aedf5aa0de657ba637b39",
        "feedfacedeadbeeffeedfacedeadbeef" + "abaddad2",
        "9313225df88406e555909c5aff5269aa"
            + "6a7a9538534f7da1e4c303d2a318a728"
            + "c3c0c95156809539fcf0e2429a6b5254"
            + "16aedbf5a0de6a57a637b39b",
        "5a8def2f0c9e53f1f75d7853659e2a20"
            + "eeb2b22aafde6419a058ab4f6f746bf4"
            + "0fc0c3b780f244452da3ebf1c5d82cde"
            + "a2418997200ef82e44ae7e3f",
        "a44a8266ee1c8eb0c8b5d4cf5ae9f19a"),
  };

  @Test
  public void testNistVectors() throws Exception {
    for (NistTestVector t : nistTestVectors) {
      if (t.iv.length != 12 || t.tag.length != 16) {
        // We support only 12-byte IV and 16-byte tag.
        continue;
      }
      AesGcmKey key = AesGcmKey.newBuilder().setKeyValue(ByteString.copyFrom(t.keyValue)).build();
      Aead aead = manager.getPrimitive(key, Aead.class);
      try {
        byte[] ciphertext = Bytes.concat(t.iv, t.ciphertext, t.tag);
        byte[] plaintext = aead.decrypt(ciphertext, t.aad);
        assertArrayEquals(plaintext, t.plaintext);
      } catch (GeneralSecurityException e) {
        fail("Should not fail at " + t.name + ", but thrown exception " + e);
      }
    }
  }

  @Test
  public void testCiphertextSize() throws Exception {
    AesGcmKey key = factory.createKey(AesGcmKeyFormat.newBuilder().setKeySize(32).build());
    Aead aead = new AesGcmKeyManager().getPrimitive(key, Aead.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertThat(ciphertext.length)
        .isEqualTo(12 /* IV_SIZE */ + plaintext.length + 16 /* TAG_SIZE */);
  }

  @Test
  public void testAes128GcmTemplate() throws Exception {
    KeyTemplate template = AesGcmKeyManager.aes128GcmTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesGcmParameters.builder()
                .setIvSizeBytes(12)
                .setTagSizeBytes(16)
                .setKeySizeBytes(16)
                .setVariant(AesGcmParameters.Variant.TINK)
                .build());
  }

  @Test
  public void testRawAes128GcmTemplate() throws Exception {
    KeyTemplate template = AesGcmKeyManager.rawAes128GcmTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesGcmParameters.builder()
                .setIvSizeBytes(12)
                .setTagSizeBytes(16)
                .setKeySizeBytes(16)
                .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void testAes256GcmTemplate() throws Exception {
    KeyTemplate template = AesGcmKeyManager.aes256GcmTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesGcmParameters.builder()
                .setIvSizeBytes(12)
                .setTagSizeBytes(16)
                .setKeySizeBytes(32)
                .setVariant(AesGcmParameters.Variant.TINK)
                .build());
  }

  @Test
  public void testRawAes256GcmTemplate() throws Exception {
    KeyTemplate template = AesGcmKeyManager.rawAes256GcmTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesGcmParameters.builder()
                .setIvSizeBytes(12)
                .setTagSizeBytes(16)
                .setKeySizeBytes(32)
                .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void testKeyTemplatesWork() throws Exception {
    Parameters p = AesGcmKeyManager.aes128GcmTemplate().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p = AesGcmKeyManager.rawAes128GcmTemplate().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p = AesGcmKeyManager.aes256GcmTemplate().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p = AesGcmKeyManager.rawAes256GcmTemplate().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @DataPoints("templateNames")
  public static final String[] KEY_TEMPLATES =
      new String[] {
        "AES128_GCM", "AES128_GCM_RAW", "AES256_GCM", "AES256_GCM_RAW",
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
          25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35
        };
    AesGcmParameters parameters = (AesGcmParameters) KeyTemplates.get(templateName).toParameters();
    com.google.crypto.tink.aead.AesGcmKey key =
        AesGcmKeyManager.createAesGcmKeyFromRandomness(
            parameters,
            new ByteArrayInputStream(keyMaterial),
            parameters.hasIdRequirement() ? 123 : null,
            InsecureSecretKeyAccess.get());
    byte[] truncatedKeyMaterial = Arrays.copyOf(keyMaterial, parameters.getKeySizeBytes());
    Key expectedKey =
        com.google.crypto.tink.aead.AesGcmKey.builder()
            .setParameters(parameters)
            .setIdRequirement(parameters.hasIdRequirement() ? 123 : null)
            .setKeyBytes(SecretBytes.copyFrom(truncatedKeyMaterial, InsecureSecretKeyAccess.get()))
            .build();
    assertTrue(key.equalsKey(expectedKey));
  }

  @Test
  public void callingCreateTwiceGivesDifferentKeys() throws Exception {
    Parameters p = AesGcmKeyManager.aes128GcmTemplate().toParameters();
    Key key = KeysetHandle.generateNew(p).getAt(0).getKey();
    for (int i = 0; i < 1000; ++i) {
      assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().equalsKey(key)).isFalse();
    }
  }

  @Test
  public void testCreateKeyFromRandomness_slowInputStream_works() throws Exception {
    byte[] keyMaterial =
        new byte[] {
          0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
          25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35
        };
    AesGcmParameters parameters =
        AesGcmParameters.builder()
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setKeySizeBytes(32)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build();
    com.google.crypto.tink.aead.AesGcmKey key =
        AesGcmKeyManager.createAesGcmKeyFromRandomness(
            parameters, SlowInputStream.copyFrom(keyMaterial), null, InsecureSecretKeyAccess.get());
    byte[] truncatedKeyMaterial = Arrays.copyOf(keyMaterial, parameters.getKeySizeBytes());
    Key expectedKey =
        com.google.crypto.tink.aead.AesGcmKey.builder()
            .setParameters(parameters)
            .setIdRequirement(null)
            .setKeyBytes(SecretBytes.copyFrom(truncatedKeyMaterial, InsecureSecretKeyAccess.get()))
            .build();
    assertTrue(key.equalsKey(expectedKey));
  }

  @Test
  public void getPrimitiveFromKeysetHandle() throws Exception {
    AesGcmParameters parameters =
        AesGcmParameters.builder()
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setKeySizeBytes(16)
            .setVariant(AesGcmParameters.Variant.TINK)
            .build();
    com.google.crypto.tink.aead.AesGcmKey key =
        com.google.crypto.tink.aead.AesGcmKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(16))
            .setIdRequirement(31)
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(key).makePrimary()).build();
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] aad = "aad".getBytes(UTF_8);

    Aead aead = keysetHandle.getPrimitive(Aead.class);
    Aead directAead = AesGcmJce.create(key);

    Object unused = directAead.decrypt(aead.encrypt(plaintext, aad), aad);
    unused = aead.decrypt(directAead.encrypt(plaintext, aad), aad);
  }
}
