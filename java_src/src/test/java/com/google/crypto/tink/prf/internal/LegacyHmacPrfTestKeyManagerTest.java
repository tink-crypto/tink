// Copyright 2023 Google LLC
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

package com.google.crypto.tink.prf.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Registry;
import com.google.crypto.tink.prf.Prf;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacPrfKey;
import com.google.crypto.tink.proto.HmacPrfParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Hex;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class LegacyHmacPrfTestKeyManagerTest {
  /** Type url that this manager supports. */
  public static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.HmacPrfKey";

  @BeforeClass
  public static void setUp() throws Exception {
    LegacyHmacPrfTestKeyManager.register();
  }

  @Test
  public void getPrimitive_works() throws Exception {
    HmacPrfParams params = HmacPrfParams.newBuilder().setHash(HashType.SHA256).build();
    HmacPrfKey key =
        HmacPrfKey.newBuilder()
            .setKeyValue(
                ByteString.copyFrom(
                    Hex.decode("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd")))
            .setParams(params)
            .setVersion(0)
            .build();
    KeyData keyData =
        KeyData.newBuilder()
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .setTypeUrl(TYPE_URL)
            .setValue(key.toByteString())
            .build();

    Prf prf = Registry.getPrimitive(keyData, Prf.class);

    assertThat(Hex.encode(prf.compute(Hex.decode("abcdefabcdefabcd"), 16)))
        .isEqualTo("4bbb72a24f348513f9474e333975cea5");
  }

  @Test
  public void getPrimitive_differentHashType_works() throws Exception {
    HmacPrfParams params = HmacPrfParams.newBuilder().setHash(HashType.SHA512).build();
    HmacPrfKey key =
        HmacPrfKey.newBuilder()
            .setKeyValue(
                ByteString.copyFrom(
                    Hex.decode("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd")))
            .setParams(params)
            .setVersion(0)
            .build();
    KeyData keyData =
        KeyData.newBuilder()
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .setTypeUrl(TYPE_URL)
            .setValue(key.toByteString())
            .build();

    Prf prf = Registry.getPrimitive(keyData, Prf.class);

    assertThat(Hex.encode(prf.compute(Hex.decode("abcdefabcdefabcd"), 16)))
        .isEqualTo("70d7e00fa8365ac54d59f5d66c711cdf");
  }

  @Test
  public void getPrimitive_wrongHash_throws() throws Exception {
    HmacPrfParams params = HmacPrfParams.newBuilder().setHashValue(13).build();
    HmacPrfKey key =
        HmacPrfKey.newBuilder()
            .setKeyValue(
                ByteString.copyFrom(
                    Hex.decode("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd")))
            .setParams(params)
            .setVersion(0)
            .build();
    KeyData keyData =
        KeyData.newBuilder()
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .setTypeUrl(TYPE_URL)
            .setValue(key.toByteString())
            .build();

    assertThrows(GeneralSecurityException.class, () -> Registry.getPrimitive(keyData, Prf.class));
  }

  @Test
  public void getPrimitive_differentKeySize_works() throws Exception {
    HmacPrfParams params = HmacPrfParams.newBuilder().setHash(HashType.SHA256).build();
    HmacPrfKey key =
        HmacPrfKey.newBuilder()
            .setKeyValue(ByteString.copyFrom(Hex.decode("abcdefabcdefabcdefabcdefabcdefab")))
            .setParams(params)
            .setVersion(0)
            .build();
    KeyData keyData =
        KeyData.newBuilder()
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .setTypeUrl(TYPE_URL)
            .setValue(key.toByteString())
            .build();

    Prf prf = Registry.getPrimitive(keyData, Prf.class);

    assertThat(Hex.encode(prf.compute(Hex.decode("abcdefabcdefabcd"), 16)))
        .isEqualTo("20e75989c99ee65f9ab62cdd642e5c64");
  }

  @Test
  public void getPrimitive_wrongKeySize_throws() throws Exception {
    HmacPrfParams params = HmacPrfParams.newBuilder().setHash(HashType.SHA256).build();
    HmacPrfKey key =
        HmacPrfKey.newBuilder()
            .setKeyValue(
                ByteString.copyFrom(Hex.decode("abcdef")))
            .setParams(params)
            .setVersion(0)
            .build();
    KeyData keyData =
        KeyData.newBuilder()
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .setTypeUrl(TYPE_URL)
            .setValue(key.toByteString())
            .build();

    assertThrows(GeneralSecurityException.class, () -> Registry.getPrimitive(keyData, Prf.class));
  }
}
