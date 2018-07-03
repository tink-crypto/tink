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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.proto.AesEaxKey;
import com.google.crypto.tink.proto.AesEaxKeyFormat;
import com.google.crypto.tink.proto.AesEaxParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Test for AesEaxJce and its key manager.
 */
@RunWith(JUnit4.class)
public class AesEaxKeyManagerTest {
  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    AeadConfig.register();
  }

  @Test
  public void testNewKeyMultipleTimes() throws Exception {
    AesEaxKeyFormat eaxKeyFormat = AesEaxKeyFormat.newBuilder()
        .setParams(AesEaxParams.newBuilder().setIvSize(16).build())
        .setKeySize(16)
        .build();
    ByteString serialized = ByteString.copyFrom(eaxKeyFormat.toByteArray());
    KeyTemplate keyTemplate = KeyTemplate.newBuilder()
        .setTypeUrl(AesEaxKeyManager.TYPE_URL)
        .setValue(serialized)
        .build();
    AesEaxKeyManager keyManager = new AesEaxKeyManager();
    Set<String> keys = new TreeSet<String>();
    // Calls newKey multiple times and make sure that they generate different keys.
    int numTests = 27;
    for (int i = 0; i < numTests / 3; i++) {
      AesEaxKey key = (AesEaxKey) keyManager.newKey(eaxKeyFormat);
      keys.add(TestUtil.hexEncode(key.getKeyValue().toByteArray()));
      assertEquals(16, key.getKeyValue().toByteArray().length);

      key = (AesEaxKey) keyManager.newKey(serialized);
      keys.add(TestUtil.hexEncode(key.getKeyValue().toByteArray()));
      assertEquals(16, key.getKeyValue().toByteArray().length);

      KeyData keyData = keyManager.newKeyData(keyTemplate.getValue());
      key = AesEaxKey.parseFrom(keyData.getValue());
      keys.add(TestUtil.hexEncode(key.getKeyValue().toByteArray()));
      assertEquals(16, key.getKeyValue().toByteArray().length);
    }
    assertEquals(numTests, keys.size());
  }

  @Test
  public void testNewKeyWithCorruptedFormat() throws Exception {
    ByteString serialized = ByteString.copyFrom(new byte[128]);
    KeyTemplate keyTemplate = KeyTemplate.newBuilder()
        .setTypeUrl(AesEaxKeyManager.TYPE_URL)
        .setValue(serialized)
        .build();
    AesEaxKeyManager keyManager = new AesEaxKeyManager();
    try {
      keyManager.newKey(serialized);
      fail("Corrupted format, should have thrown exception");
    } catch (GeneralSecurityException expected) {
      // Expected
    }
    try {
      keyManager.newKeyData(keyTemplate.getValue());
      fail("Corrupted format, should have thrown exception");
    } catch (GeneralSecurityException expected) {
      // Expected
    }
  }

  private static final int AES_KEY_SIZE = 16;

  private static class PublicTestVector {
    String name;
    public byte[] keyValue;
    public byte[] plaintext;
    public byte[] aad;
    public byte[] iv;
    public byte[] ciphertext;
    public byte[] tag;
    public PublicTestVector(String name, String keyValue, String plaintext, String aad,
        String iv, String ciphertext, String tag) {
      try {
        this.name = name;
        this.keyValue = TestUtil.hexDecode(keyValue);
        this.plaintext = TestUtil.hexDecode(plaintext);
        this.aad = TestUtil.hexDecode(aad);
        this.iv = TestUtil.hexDecode(iv);
        this.ciphertext = TestUtil.hexDecode(ciphertext);
        this.tag = TestUtil.hexDecode(tag);
      } catch (Exception ignored) {
        // Ignored
      }
    }
  }

  // Test vectors from
  // http://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf.
  PublicTestVector[] publicTestVectors = {
      new PublicTestVector(
          "Test Case 1",
          "233952dee4d5ed5f9b9c6d6ff80ff478",
          "",
          "6bfb914fd07eae6b",
          "62ec67f9c3a4a407fcb2a8c49031a8b3",
          "",
          "e037830e8389f27b025a2d6527e79d01"),
      new PublicTestVector(
          "Test Case 2",
          "91945d3f4dcbee0bf45ef52255f095a4",
          "f7fb",
          "fa3bfd4806eb53fa",
          "becaf043b0a23d843194ba972c66debd",
          "19dd",
          "5c4c9331049d0bdab0277408f67967e5"),
      new PublicTestVector(
          "Test Case 3",
          "01f74ad64077f2e704c0f60ada3dd523",
          "1a47cb4933",
          "234a3463c1264ac6",
          "70c3db4f0d26368400a10ed05d2bff5e",
          "d851d5bae0",
          "3a59f238a23e39199dc9266626c40f80"),
      new PublicTestVector(
          "Test Case 4",
          "d07cf6cbb7f313bdde66b727afd3c5e8",
          "481c9e39b1",
          "33cce2eabff5a79d",
          "8408dfff3c1a2b1292dc199e46b7d617",
          "632a9d131a",
          "d4c168a4225d8e1ff755939974a7bede"),
      new PublicTestVector(
          "Test Case 5",
          "35b6d0580005bbc12b0587124557d2c2",
          "40d0c07da5e4",
          "aeb96eaebe2970e9",
          "fdb6b06676eedc5c61d74276e1f8e816",
          "071dfe16c675",
          "cb0677e536f73afe6a14b74ee49844dd"),
      new PublicTestVector(
          "Test Case 6",
          "bd8e6e11475e60b268784c38c62feb22",
          "4de3b35c3fc039245bd1fb7d",
          "d4482d1ca78dce0f",
          "6eac5c93072d8e8513f750935e46da1b",
          "835bb4f15d743e350e728414",
          "abb8644fd6ccb86947c5e10590210a4f"),
      new PublicTestVector(
          "Test Case 7",
          "7c77d6e813bed5ac98baa417477a2e7d",
          "8b0a79306c9ce7ed99dae4f87f8dd61636",
          "65d2017990d62528",
          "1a8c98dcd73d38393b2bf1569deefc19",
          "02083e3979da014812f59f11d52630da30",
          "137327d10649b0aa6e1c181db617d7f2"),
      new PublicTestVector(
          "Test Case 8",
          "5fff20cafab119ca2fc73549e20f5b0d",
          "1bda122bce8a8dbaf1877d962b8592dd2d56",
          "54b9f04e6a09189a",
          "dde59b97d722156d4d9aff2bc7559826",
          "2ec47b2c4954a489afc7ba4897edcdae8cc3",
          "3b60450599bd02c96382902aef7f832a"),
      new PublicTestVector(
          "Test Case 9",
          "a4a4782bcffd3ec5e7ef6d8c34a56123",
          "6cf36720872b8513f6eab1a8a44438d5ef11",
          "899a175897561d7e",
          "b781fcf2f75fa5a8de97a9ca48e522ec",
          "0de18fd0fdd91e7af19f1d8ee8733938b1e8",
          "e7f6d2231618102fdb7fe55ff1991700"),
      new PublicTestVector(
          "Test Case 10",
          "8395fcf1e95bebd697bd010bc766aac3",
          "ca40d7446e545ffaed3bd12a740a659ffbbb3ceab7",
          "126735fcc320d25a",
          "22e7add93cfc6393c57ec0b3c17d6b44",
          "cb8920f87a6c75cff39627b56e3ed197c552d295a7",
          "cfc46afc253b4652b1af3795b124ab6e"),
  };

  @Test
  public void testPublicTestVectors() throws Exception {
    for (PublicTestVector t : publicTestVectors) {
      if (TestUtil.shouldSkipTestWithAesKeySize(t.keyValue.length)) {
        continue;
      }
      Aead aead = getRawAesEax(t.keyValue, t.iv.length);
      try {
        byte[] ciphertext = Bytes.concat(t.iv, t.ciphertext, t.tag);
        byte[] plaintext = aead.decrypt(ciphertext, t.aad);
        assertArrayEquals(plaintext, t.plaintext);
      } catch (GeneralSecurityException e) {
        fail("Should not fail at " + t.name + ", but thrown exception " + e);
      }
    }
  }

  private Aead getRawAesEax(byte[] keyValue, int ivSizeInBytes) throws Exception {
    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createAesEaxKeyData(keyValue, ivSizeInBytes),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.RAW)));
    return AeadFactory.getPrimitive(keysetHandle);
  }

  @Test
  public void testBasic() throws Exception {
    byte[] keyValue = Random.randBytes(AES_KEY_SIZE);
    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createAesEaxKeyData(keyValue, 12),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK)));
    TestUtil.runBasicAeadFactoryTests(keysetHandle);
  }

  @Test
  public void testCiphertextSize() throws Exception {
    byte[] keyValue = Random.randBytes(AES_KEY_SIZE);
    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createAesEaxKeyData(keyValue, 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK)));
    Aead aead = AeadFactory.getPrimitive(keysetHandle);
    byte[] plaintext = "plaintext".getBytes("UTF-8");
    byte[] associatedData = "associatedData".getBytes("UTF-8");
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertEquals(
        CryptoFormat.NON_RAW_PREFIX_SIZE + 16 /* IV_SIZE */ + plaintext.length + 16 /* TAG_SIZE */,
        ciphertext.length);
  }
}
