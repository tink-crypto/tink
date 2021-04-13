// Copyright 2019 Google LLC
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

package com.google.crypto.tink.testing;

import static org.junit.Assert.fail;

import com.google.crypto.tink.aead.AesGcmKeyManager;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class CompareKeysetsTest {
  @BeforeClass
  public static void registerAesGcm() throws Exception {
    AesGcmKeyManager.register(true);
  }

  private static final byte[] KEY_0 = TestUtil.hexDecode("000102030405060708090a0b0c0d0e0f");
  private static final byte[] KEY_1 = TestUtil.hexDecode("100102030405060708090a0b0c0d0e0f");
  private static final byte[] KEY_2 = TestUtil.hexDecode("200102030405060708090a0b0c0d0e0f");
  private static final byte[] KEY_3 = TestUtil.hexDecode("300102030405060708090a0b0c0d0e0f");
  private static final byte[] KEY_4 = TestUtil.hexDecode("400102030405060708090a0b0c0d0e0f");
  private static final byte[] KEY_5 = TestUtil.hexDecode("500102030405060708090a0b0c0d0e0f");
  private static final byte[] KEY_6 = TestUtil.hexDecode("600102030405060708090a0b0c0d0e0f");

  private static Keyset.Key aesGcmKey(
      byte[] keyValue, int keyId, KeyStatusType status, OutputPrefixType prefixType)
      throws Exception {
    return TestUtil.createKey(TestUtil.createAesGcmKeyData(keyValue), keyId, status, prefixType);
  }

  @Test
  public void testCompareKeysets_emptyKeysets_equal() throws Exception {
    CompareKeysets.compareKeysets(Keyset.getDefaultInstance(),
        Keyset.getDefaultInstance());
  }

  @Test
  public void testCompareKeysets_singleKey_equal() throws Exception {
    Keyset keyset1 =
        Keyset.newBuilder()
            .addKey(aesGcmKey(KEY_0, 17, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .setPrimaryKeyId(17)
            .build();
    Keyset keyset2 =
        Keyset.newBuilder()
            .addKey(aesGcmKey(KEY_0, 17, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .setPrimaryKeyId(17)
            .build();
    CompareKeysets.compareKeysets(keyset1, keyset2);
  }

  @Test
  public void testCompareKeysets_twoKeys_equal() throws Exception {
    Keyset keyset1 =
        Keyset.newBuilder()
            .addKey(aesGcmKey(KEY_0, 17, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_1, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .setPrimaryKeyId(17)
            .build();
    Keyset keyset2 =
        Keyset.newBuilder()
            .addKey(aesGcmKey(KEY_0, 17, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_1, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .setPrimaryKeyId(17)
            .build();
    CompareKeysets.compareKeysets(keyset1, keyset2);
  }

  @Test
  public void testCompareKeysets_twoKeysDifferentOrder_equal() throws Exception {
    Keyset keyset1 =
        Keyset.newBuilder()
            .addKey(aesGcmKey(KEY_0, 17, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_1, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .setPrimaryKeyId(17)
            .build();
    Keyset keyset2 =
        Keyset.newBuilder()
            .addKey(aesGcmKey(KEY_1, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_0, 17, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .setPrimaryKeyId(17)
            .build();
    CompareKeysets.compareKeysets(keyset1, keyset2);
  }

  @Test
  public void testCompareKeysets_twoKeysDifferentPrimary_throws() throws Exception {
    Keyset keyset1 =
        Keyset.newBuilder()
            .addKey(aesGcmKey(KEY_0, 17, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_1, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .setPrimaryKeyId(17)
            .build();
    Keyset keyset2 =
        Keyset.newBuilder()
            .addKey(aesGcmKey(KEY_0, 17, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_1, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .setPrimaryKeyId(18)
            .build();
    try {
      CompareKeysets.compareKeysets(keyset1, keyset2);
      fail();
    } catch (Exception e) {
      // expected.
    }
  }

  @Test
  public void testCompareKeysets_singleKeyDifferentStatus_throws() throws Exception {
    Keyset keyset1 =
        Keyset.newBuilder()
            .addKey(aesGcmKey(KEY_0, 17, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .setPrimaryKeyId(17)
            .build();
    Keyset keyset2 =
        Keyset.newBuilder()
            .addKey(aesGcmKey(KEY_0, 17, KeyStatusType.DISABLED, OutputPrefixType.TINK))
            .setPrimaryKeyId(17)
            .build();
    try {
      CompareKeysets.compareKeysets(keyset1, keyset2);
      fail();
    } catch (Exception e) {
      // expected.
    }
  }

  @Test
  public void testCompareKeysets_singleKeyDifferentOutputPrefix_throws() throws Exception {
    Keyset keyset1 =
        Keyset.newBuilder()
            .addKey(aesGcmKey(KEY_0, 17, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .setPrimaryKeyId(17)
            .build();
    Keyset keyset2 =
        Keyset.newBuilder()
            .addKey(aesGcmKey(KEY_0, 17, KeyStatusType.ENABLED, OutputPrefixType.RAW))
            .setPrimaryKeyId(17)
            .build();
    try {
      CompareKeysets.compareKeysets(keyset1, keyset2);
      fail();
    } catch (Exception e) {
      // expected.
    }
  }

  @Test
  public void testCompareKeysets_singleKeyDifferentKeyMaterial_throws() throws Exception {
    Keyset keyset1 =
        Keyset.newBuilder()
            .addKey(aesGcmKey(KEY_0, 17, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .setPrimaryKeyId(17)
            .build();
    Keyset.Key key = keyset1.getKey(0);
    Keyset keyset2 =
        Keyset.newBuilder()
            .addKey(
                Keyset.Key.newBuilder(key)
                    .setKeyData(
                        KeyData.newBuilder(key.getKeyData())
                            .setKeyMaterialType(KeyMaterialType.UNKNOWN_KEYMATERIAL)))
            .setPrimaryKeyId(17)
            .build();
    try {
      CompareKeysets.compareKeysets(keyset1, keyset2);
      fail();
    } catch (Exception e) {
      // expected.
    }
  }

  @Test
  public void testCompareKeysets_differentKeyIdButRawOutputPrefix_throws() throws Exception {
    Keyset keyset1 =
        Keyset.newBuilder()
            .addKey(aesGcmKey(KEY_0, 18, KeyStatusType.ENABLED, OutputPrefixType.RAW))
            .setPrimaryKeyId(18)
            .build();
    Keyset keyset2 =
        Keyset.newBuilder()
            .addKey(aesGcmKey(KEY_0, 17, KeyStatusType.ENABLED, OutputPrefixType.RAW))
            .setPrimaryKeyId(17)
            .build();
    try {
      CompareKeysets.compareKeysets(keyset1, keyset2);
      fail();
    } catch (Exception e) {
      // expected.
    }
  }

  @Test
  public void testCompareKeysets_sameKeysSameIdsDifferentOrder_throws() throws Exception {
    Keyset keyset1 =
        Keyset.newBuilder()
            .addKey(aesGcmKey(KEY_0, 17, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_1, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_2, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_3, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_4, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_5, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_6, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .setPrimaryKeyId(17)
            .build();
    Keyset keyset2 =
        Keyset.newBuilder()
            .addKey(aesGcmKey(KEY_3, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_1, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_0, 17, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_2, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_5, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_4, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_6, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .setPrimaryKeyId(17)
            .build();
      CompareKeysets.compareKeysets(keyset1, keyset2);
  }

  @Test
  public void testCompareKeysets_differentKeysSameIdsSimlarOrder_throws() throws Exception {
    Keyset keyset1 =
        Keyset.newBuilder()
            .addKey(aesGcmKey(KEY_0, 17, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_1, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_2, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_3, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_4, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_5, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .setPrimaryKeyId(17)
            .build();
    Keyset keyset2 =
        Keyset.newBuilder()
            .addKey(aesGcmKey(KEY_0, 17, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_1, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_2, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_6, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK)) // != KEY_3
            .addKey(aesGcmKey(KEY_4, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .addKey(aesGcmKey(KEY_5, 18, KeyStatusType.ENABLED, OutputPrefixType.TINK))
            .setPrimaryKeyId(17)
            .build();
    try {
      CompareKeysets.compareKeysets(keyset1, keyset2);
      fail();
    } catch (Exception e) {
      // expected.
    }
  }
}
