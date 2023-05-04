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
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.aead.AesGcmKeyManager;
import com.google.crypto.tink.prf.HkdfPrfKeyManager;
import com.google.crypto.tink.proto.AesGcmKey;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HkdfPrfKey;
import com.google.crypto.tink.proto.HkdfPrfParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for PrfBasedDeriver */
@RunWith(JUnit4.class)
public final class PrfBasedDeriverTest {
  @BeforeClass
  public static void addRequiredKeyManagers() throws Exception {
    AesGcmKeyManager.register(true);
    HkdfPrfKeyManager.register(true);
  }

  @Test
  public void createDeriver_works() throws Exception {
    HkdfPrfKey key =
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .setKeyValue(ByteString.copyFrom(Random.randBytes(32)))
            .build();
    Object unused =
        PrfBasedDeriver.create(
            TestUtil.createKeyData(
                key, HkdfPrfKeyManager.staticKeyType(), KeyData.KeyMaterialType.SYMMETRIC),
            AeadKeyTemplates.AES128_GCM);
  }

  @Test
  public void createDeriver_invalidPrfKey_throws() throws Exception {
    HkdfPrfKey key =
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.UNKNOWN_HASH))
            .setKeyValue(ByteString.copyFrom(Random.randBytes(32)))
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            PrfBasedDeriver.create(
                TestUtil.createKeyData(
                    key, HkdfPrfKeyManager.staticKeyType(), KeyData.KeyMaterialType.SYMMETRIC),
                AeadKeyTemplates.AES256_GCM));
  }

  @Test
  public void createDeriver_invalidDerivedKeyTemplate_throws() throws Exception {
    HkdfPrfKey key =
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .setKeyValue(ByteString.copyFrom(Random.randBytes(32)))
            .build();
    KeyTemplate keyTemplate = KeyTemplate.newBuilder().setTypeUrl("non existent type url").build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            PrfBasedDeriver.create(
                TestUtil.createKeyData(
                    key, HkdfPrfKeyManager.staticKeyType(), KeyData.KeyMaterialType.SYMMETRIC),
                keyTemplate));
  }

  /**
   * TestVector from Rfc5869, test case 2: https://tools.ietf.org/html/rfc5869#appendix-A.2 We
   * simply take the first 32 bytes of the test vector.
   */
  @Test
  public void deriveKey_testVector() throws Exception {
    HkdfPrfKey key =
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setParams(
                HkdfPrfParams.newBuilder()
                    .setSalt(
                        ByteString.copyFrom(
                            Hex.decode(
                                "606162636465666768696a6b6c6d6e6f"
                                    + "707172737475767778797a7b7c7d7e7f"
                                    + "808182838485868788898a8b8c8d8e8f"
                                    + "909192939495969798999a9b9c9d9e9f"
                                    + "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")))
                    .setHash(HashType.SHA256))
            .setKeyValue(
                ByteString.copyFrom(
                    Hex.decode(
                        "000102030405060708090a0b0c0d0e0f"
                            + "101112131415161718191a1b1c1d1e1f"
                            + "202122232425262728292a2b2c2d2e2f"
                            + "303132333435363738393a3b3c3d3e3f"
                            + "404142434445464748494a4b4c4d4e4f")))
            .build();
    PrfBasedDeriver deriver =
        PrfBasedDeriver.create(
            TestUtil.createKeyData(
                key, HkdfPrfKeyManager.staticKeyType(), KeyData.KeyMaterialType.SYMMETRIC),
            AeadKeyTemplates.AES256_GCM);

    KeysetHandle handle =
        deriver.deriveKeyset(
            Hex.decode(
                "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                    + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                    + "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                    + "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                    + "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));

    Keyset keyset = CleartextKeysetHandle.getKeyset(handle);

    assertThat(keyset.getKeyList()).hasSize(1);
    assertThat(keyset.getKey(0).getKeyData().getTypeUrl()).isEqualTo(AeadConfig.AES_GCM_TYPE_URL);
    assertThat(keyset.getKey(0).getKeyData().getKeyMaterialType())
        .isEqualTo(KeyData.KeyMaterialType.SYMMETRIC);

    AesGcmKey aesGcmKey =
        AesGcmKey.parseFrom(
            keyset.getKey(0).getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(Hex.encode(aesGcmKey.getKeyValue().toByteArray()))
        .isEqualTo("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c");
  }

  /** Tests the keyset values which should not be set (as we are only deriving KeyData). */
  @Test
  public void deriveKey_checkKeysetValues() throws Exception {
    HkdfPrfKey key =
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .setKeyValue(ByteString.copyFrom(Random.randBytes(32)))
            .build();
    KeysetHandle handle =
        PrfBasedDeriver.create(
                TestUtil.createKeyData(
                    key, HkdfPrfKeyManager.staticKeyType(), KeyData.KeyMaterialType.SYMMETRIC),
                AeadKeyTemplates.AES128_GCM)
            .deriveKeyset(Random.randBytes(10));
    Keyset keyset = CleartextKeysetHandle.getKeyset(handle);

    assertThat(keyset.getPrimaryKeyId()).isEqualTo(0);
    assertThat(keyset.getKeyList()).hasSize(1);
    assertThat(keyset.getKey(0).getStatus()).isEqualTo(KeyStatusType.UNKNOWN_STATUS);
    assertThat(keyset.getKey(0).getKeyId()).isEqualTo(0);
    assertThat(keyset.getKey(0).getOutputPrefixType()).isEqualTo(OutputPrefixType.UNKNOWN_PREFIX);
  }

  private static PrfBasedDeriver hkdfSha512DeriverForAes128Gcm(ByteString keyValue)
      throws Exception {
    return PrfBasedDeriver.create(
        TestUtil.createKeyData(
            HkdfPrfKey.newBuilder()
                .setVersion(0)
                .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA512))
                .setKeyValue(keyValue)
                .build(),
            HkdfPrfKeyManager.staticKeyType(),
            KeyData.KeyMaterialType.SYMMETRIC),
        AeadKeyTemplates.AES128_GCM);
  }

  // Check that keys with zero appended will create different derivated keys.
  @Test
  public void createDeriver_compareToKeyWithZeroAppended() throws Exception {
    // Create a key with a zero in the end.
    byte[] keyValue = Random.randBytes(33);
    keyValue[32] = 0;
    PrfBasedDeriver deriver1 = hkdfSha512DeriverForAes128Gcm(ByteString.copyFrom(keyValue, 0, 32));
    PrfBasedDeriver deriver2 = hkdfSha512DeriverForAes128Gcm(ByteString.copyFrom(keyValue, 0, 33));
    Keyset keyset1 =
        CleartextKeysetHandle.getKeyset(deriver1.deriveKeyset("some salt".getBytes(UTF_8)));
    Keyset keyset2 =
        CleartextKeysetHandle.getKeyset(deriver2.deriveKeyset("some salt".getBytes(UTF_8)));
    AesGcmKey aesGcmKey1 =
        AesGcmKey.parseFrom(
            keyset1.getKey(0).getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    AesGcmKey aesGcmKey2 =
        AesGcmKey.parseFrom(
            keyset2.getKey(0).getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(aesGcmKey1.getKeyValue()).hasSize(16);
    assertThat(aesGcmKey2.getKeyValue()).hasSize(16);
    assertThat(aesGcmKey1.getKeyValue()).isNotEqualTo(aesGcmKey2.getKeyValue());
  }

  // Check that salt with zero appended will create different derivated keys.
  // The main reason for this test is to assure that HKDF is used properly.
  // HKDF makes an (implicit?) assumption that the salt has constant size or
  // at least is not chosen by a third party. There are salt values that are
  // equivalent to each other. E.g. appending a zero byte to a salt < 64 bytes
  // does not change the output. Or a salt > 64 bytes and its hash digest are
  // equivalent. Hence an argument that is potentially coming from a third party
  // should be passed to HKDF as parmeter info.
  @Test
  public void createDeriver_compareToSaltWithZeroAppended() throws Exception {
    // Create a key with a zero in the end.
    byte[] keyValue = Random.randBytes(32);
    PrfBasedDeriver deriver = hkdfSha512DeriverForAes128Gcm(ByteString.copyFrom(keyValue));
    Keyset keyset1 = CleartextKeysetHandle.getKeyset(deriver.deriveKeyset(new byte[20]));
    Keyset keyset2 = CleartextKeysetHandle.getKeyset(deriver.deriveKeyset(new byte[21]));
    AesGcmKey aesGcmKey1 =
        AesGcmKey.parseFrom(
            keyset1.getKey(0).getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    AesGcmKey aesGcmKey2 =
        AesGcmKey.parseFrom(
            keyset2.getKey(0).getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(aesGcmKey1.getKeyValue()).hasSize(16);
    assertThat(aesGcmKey2.getKeyValue()).hasSize(16);
    assertThat(aesGcmKey1.getKeyValue()).isNotEqualTo(aesGcmKey2.getKeyValue());
  }

  // Test Vector for a key ending in 0, genereted in this implementation.
  @Test
  public void createDeriver_zeroEndingKeyTestVector() throws Exception {
    HkdfPrfKey key =
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA512))
            .setKeyValue(
                ByteString.copyFrom(
                    Hex.decode(
                        "a1a2a3a4a5a6a7a8a9aaabacadaeafb1b2b3b4b5b6b7b8b9babbbcbdbebf"
                            + "c1c2c3c4c5c6c7c8c9cacbcccdcecfc1c2c3c4c5c6c7c8c9cacbcccdcecf"
                            + "00")))
            .build();
    PrfBasedDeriver deriver =
        PrfBasedDeriver.create(
            TestUtil.createKeyData(
                key, HkdfPrfKeyManager.staticKeyType(), KeyData.KeyMaterialType.SYMMETRIC),
            AeadKeyTemplates.AES128_GCM);

    KeysetHandle handle = deriver.deriveKeyset(Hex.decode("1122334455"));

    Keyset keyset = CleartextKeysetHandle.getKeyset(handle);

    AesGcmKey aesGcmKey =
        AesGcmKey.parseFrom(
            keyset.getKey(0).getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(Hex.encode(aesGcmKey.getKeyValue().toByteArray()))
        .isEqualTo("31c449af66b669b9963ef2df30dfe5f9");
  }

  // Test Vector for a key generated with input/salt ending in 0, genereted in this implementation.
  @Test
  public void createDeriver_zeroEndingSaltTestVector() throws Exception {
    HkdfPrfKey key =
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA512))
            .setKeyValue(
                ByteString.copyFrom(
                    Hex.decode(
                        "c1c2c3c4c5c6c7c8c9cacbcccdcecfc1c2c3c4c5c6c7c8c9cacbcccdcecf"
                            + "a1a2a3a4a5a6a7a8a9aaabacadaeafb1b2b3b4b5b6b7b8b9babbbcbdbebf")))
            .build();
    PrfBasedDeriver deriver =
        PrfBasedDeriver.create(
            TestUtil.createKeyData(
                key, HkdfPrfKeyManager.staticKeyType(), KeyData.KeyMaterialType.SYMMETRIC),
            AeadKeyTemplates.AES128_GCM);

    KeysetHandle handle = deriver.deriveKeyset(Hex.decode("00"));

    Keyset keyset = CleartextKeysetHandle.getKeyset(handle);

    AesGcmKey aesGcmKey =
        AesGcmKey.parseFrom(
            keyset.getKey(0).getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(Hex.encode(aesGcmKey.getKeyValue().toByteArray()))
        .isEqualTo("887af0808c1855eba1594bf540adb957");
  }

  // Test Vector for a key generated with empty salt.
  @Test
  public void createDeriver_emptySaltTestVector() throws Exception {
    HkdfPrfKey key =
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA512))
            .setKeyValue(
                ByteString.copyFrom(
                    Hex.decode(
                        "c1c2c3c4c5c6c7c8c9cacbcccdcecfc1c2c3c4c5c6c7c8c9cacbcccdcecf"
                            + "a1a2a3a4a5a6a7a8a9aaabacadaeafb1b2b3b4b5b6b7b8b9babbbcbdbebf")))
            .build();
    PrfBasedDeriver deriver =
        PrfBasedDeriver.create(
            TestUtil.createKeyData(
                key, HkdfPrfKeyManager.staticKeyType(), KeyData.KeyMaterialType.SYMMETRIC),
            AeadKeyTemplates.AES128_GCM);

    KeysetHandle handle = deriver.deriveKeyset(new byte[0]);

    Keyset keyset = CleartextKeysetHandle.getKeyset(handle);

    AesGcmKey aesGcmKey =
        AesGcmKey.parseFrom(
            keyset.getKey(0).getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(Hex.encode(aesGcmKey.getKeyValue().toByteArray()))
        .isEqualTo("fb2b448c2595caf75129e282af758bf1");
  }
}
