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

package com.google.crypto.tink.aead.internal;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.AesCtrHmacAeadKey;
import com.google.crypto.tink.proto.AesCtrKey;
import com.google.crypto.tink.proto.AesCtrParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.crypto.tink.subtle.Hex;
import com.google.protobuf.ByteString;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class LegacyAesCtrHmacTestKeyManagerTest {

  private static final String TYPE_URL = "type.googleapis.com/custom.AesCtrHmacAeadKey";

  @BeforeClass
  public static void setUp() throws Exception {
    LegacyAesCtrHmacTestKeyManager.register();
  }

  @Test
  public void getPrimitive_works() throws Exception {
    AesCtrKey aesCtrKey =
        AesCtrKey.newBuilder()
            .setKeyValue(ByteString.copyFrom(Hex.decode("abcdefabcdefabcdefabcdefabcdefab")))
            .setParams(AesCtrParams.newBuilder().setIvSize(16).build())
            .build();
    HmacKey hmacKey =
        HmacKey.newBuilder()
            .setParams(HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(32))
            .setKeyValue(
                ByteString.copyFrom(
                    Hex.decode("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd")))
            .build();
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.newBuilder().setAesCtrKey(aesCtrKey).setHmacKey(hmacKey).build();
    KeyData keyData =
        KeyData.newBuilder()
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .setTypeUrl(TYPE_URL)
            .setValue(key.toByteString())
            .build();

    Aead aead = Registry.getPrimitive(keyData, Aead.class);

    assertThat(aead).isNotNull();
    assertThat(aead).isInstanceOf(EncryptThenAuthenticate.class);
  }

  @Test
  public void getPrimitive_encryptDecrypt_works() throws Exception {
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] aad = "aad".getBytes(UTF_8);
    AesCtrKey aesCtrKey =
        AesCtrKey.newBuilder()
            .setKeyValue(ByteString.copyFrom(Hex.decode("abcdefabcdefabcdefabcdefabcdefab")))
            .setParams(AesCtrParams.newBuilder().setIvSize(16).build())
            .build();
    HmacKey hmacKey =
        HmacKey.newBuilder()
            .setParams(HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(32))
            .setKeyValue(
                ByteString.copyFrom(
                    Hex.decode("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd")))
            .build();
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.newBuilder().setAesCtrKey(aesCtrKey).setHmacKey(hmacKey).build();
    KeyData keyData =
        KeyData.newBuilder()
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .setTypeUrl(TYPE_URL)
            .setValue(key.toByteString())
            .build();

    Aead aead = Registry.getPrimitive(keyData, Aead.class);

    assertThat(aead.decrypt(aead.encrypt(plaintext, aad), aad)).isEqualTo(plaintext);
  }
}
