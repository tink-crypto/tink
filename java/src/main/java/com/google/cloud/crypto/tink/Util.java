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

import com.google.cloud.crypto.tink.TinkProto.Keyset;
import com.google.cloud.crypto.tink.TinkProto.KeysetInfo;

/**
 * Various helpers.
 */
public class Util {
  /**
   * @return a KeysetInfo-proto from a {@code keyset} protobuf.
   */
  public static KeysetInfo getKeysetInfo(Keyset keyset) {
    KeysetInfo.Builder info = KeysetInfo.newBuilder()
        .setPrimaryKeyId(keyset.getPrimaryKeyId());
    for (Keyset.Key key : keyset.getKeyList()) {
      info.addKeyInfo(getKeyInfo(key));
    }
    return info.build();
  }

  /**
   * @return a KeyInfo-proto from a {@code key} protobuf.
   */
  public static KeysetInfo.KeyInfo getKeyInfo(Keyset.Key key) {
    return KeysetInfo.KeyInfo.newBuilder()
        .setTypeUrl(key.getKeyData().getTypeUrl())
        .setStatus(key.getStatus())
        .setOutputPrefixType(key.getOutputPrefixType())
        .setKeyId(key.getKeyId())
        .setGeneratedAt(key.getGeneratedAt())
        .setValidUntil(key.getValidUntil())
        .build();
  }
}
