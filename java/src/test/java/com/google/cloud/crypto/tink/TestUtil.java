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

package com.google.cloud.crypto.tink;

import com.google.cloud.crypto.tink.CommonProto.HashType;
import com.google.cloud.crypto.tink.HmacProto.HmacKey;
import com.google.cloud.crypto.tink.HmacProto.HmacKeyFormat;
import com.google.cloud.crypto.tink.HmacProto.HmacParams;
import com.google.cloud.crypto.tink.TinkProto.Keyset;
import com.google.cloud.crypto.tink.TinkProto.Keyset.Key;
import com.google.cloud.crypto.tink.TinkProto.Keyset.Key.PrefixType;
import com.google.cloud.crypto.tink.TinkProto.Keyset.Key.StatusType;
import com.google.cloud.crypto.tink.TinkProto.KeyFormat;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import com.google.protobuf.Message;
import com.google.protobuf.TextFormat;

/**
 * Test helpers.
 */
public class TestUtil {

  /**
   * @returns a keyset from a list of keys. The first key is primary.
   */
  public static Keyset createKeyset(Key primary, Key... keys) throws Exception {
    Keyset.Builder builder = Keyset.newBuilder();
    builder.addKey(primary)
        .setPrimaryKeyId(primary.getKeyId());
    for (Key key : keys) {
      builder.addKey(key);
    }
    return builder.build();
  }

  /**
   * @returns a key with some specific properties.
   */
  public static Key createKey(Message proto, int keyId, StatusType status, PrefixType prefixType)
      throws Exception {
    return Key.newBuilder()
        .setKeyData(Any.pack(proto))
        .setStatus(status)
        .setKeyId(keyId)
        .setPrefixType(prefixType)
        .build();
  }

  /**
   * @returns a HmacKey key.
   */
  public static HmacKey createHmacKey() throws Exception {
    HmacParams params = HmacParams.newBuilder()
        .setHash(HashType.SHA256)
        .setTagSize(16)
        .build();

    return HmacKey.newBuilder()
        .setParams(params)
        .setKey(ByteString.copyFromUtf8("12345678901234561234567890123456"))
        .build();
  }

  /**
   * @returns a keyset handle from a {@code keyset}.
   */
  public static KeysetHandle createKeysetHandle(final Keyset keyset) throws Exception {
    return new KeysetHandle() {
      @Override
      public byte[] getSource() {
        return new byte[0];
      }

      @Override
      public Keyset getKeyset() {
        return keyset;
      }
    };
  }

  /**
   * @returns a keyset handle from a {@code keyset} which must be a Keyset proto in text format.
   */
  public static KeysetHandle createKeysetHandle(final String keyset) throws Exception {
    try {
      Keyset.Builder keysetBuilder = Keyset.newBuilder();
      TextFormat.merge(keyset, keysetBuilder);
      return createKeysetHandle(keysetBuilder.build());
    } catch (Exception e) {
      System.out.println(e);
      return null;
    }
  }
}
