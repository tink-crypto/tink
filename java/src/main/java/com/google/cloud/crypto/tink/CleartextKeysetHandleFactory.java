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
import com.google.cloud.crypto.tink.TinkProto.KmsEncryptedKeyset;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.TextFormat;
import com.google.protobuf.TextFormat.ParseException;
import java.security.GeneralSecurityException;

/**
 * Creates keyset handles from cleartext keysets.
 */
public final class CleartextKeysetHandleFactory {
  /**
   * @returns a new keyset handle from {@code proto} which is a Keyset protobuf in binary format.
   * @throws GeneralSecurityException
   */
  public static final KeysetHandle fromBinaryFormat(final byte[] proto)
      throws GeneralSecurityException {
    try {
      Keyset keyset = Keyset.parseFrom(proto);
      return fromProto(keyset);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid keyset");
    }
  }

  /**
   * @returns a new keyset handle from {@code proto} which is a Keyset protobuf in text format.
   * @throws GeneralSecurityException
   */
  public static final KeysetHandle fromTextFormat(String proto) throws GeneralSecurityException {
    try {
      Keyset.Builder keysetBuilder = Keyset.newBuilder();
      TextFormat.merge(proto, keysetBuilder);
      return fromProto(keysetBuilder.build());
    } catch (ParseException e) {
      throw new GeneralSecurityException("invalid keyset");
    }
  }

  /**
   * @returns a new keyset handle from {@code encryptedKeySet}.
   * @throws GeneralSecurityException
   */
  public static final KeysetHandle fromProto(final Keyset keyset)
      throws GeneralSecurityException {
    return new KeysetHandle(keyset);
  }
}
