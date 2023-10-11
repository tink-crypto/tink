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

package com.google.crypto.tink.streamingaead.internal;

import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.AesGcmHkdfStreaming;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/**
 * Test helper key manager emulating a user that has a custom old KeyManager implementation with a
 * custom StreamingAead primitive. In order to test our code handling such cases.
 */
public class LegacyAesGcmHkdfStreamingTestKeyManager implements KeyManager<StreamingAead> {
  /** Type url that this manager does support. */
  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey";

  private static final int NONCE_PREFIX_IN_BYTES = 7;
  private static final int TAG_SIZE_IN_BYTES = 16;

  @Override
  public StreamingAead getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      AesGcmHkdfStreamingKey keyProto =
          AesGcmHkdfStreamingKey.parseFrom(serializedKey, ExtensionRegistryLite.getEmptyRegistry());
      validateKey(keyProto);
      String hkdfAlgo;
      switch (keyProto.getParams().getHkdfHashType()) {
        case SHA1:
          hkdfAlgo = "HmacSha1";
          break;
        case SHA224:
          hkdfAlgo = "HmacSha224";
          break;
        case SHA256:
          hkdfAlgo = "HmacSha256";
          break;
        case SHA384:
          hkdfAlgo = "HmacSha384";
          break;
        case SHA512:
          hkdfAlgo = "HmacSha512";
          break;
        default:
          throw new GeneralSecurityException(
              "hash unsupported for HKDF/HMAC: " + keyProto.getParams().getHkdfHashType());
      }
      return new AesGcmHkdfStreaming(
          keyProto.getKeyValue().toByteArray(),
          hkdfAlgo,
          keyProto.getParams().getDerivedKeySize(),
          keyProto.getParams().getCiphertextSegmentSize(),
          /* firstSegmentOffset= */ 0);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Expected serialized AesGcmHkdfStreamingKey proto", e);
    }
  }

  private void validateKey(AesGcmHkdfStreamingKey key) throws GeneralSecurityException {
    Validators.validateAesKeySize(key.getParams().getDerivedKeySize());
    if (key.getParams().getHkdfHashType() != HashType.SHA1
        && key.getParams().getHkdfHashType() != HashType.SHA256
        && key.getParams().getHkdfHashType() != HashType.SHA512) {
      throw new GeneralSecurityException("Invalid HKDF hash type");
    }
    if (key.getParams().getCiphertextSegmentSize()
        < key.getParams().getDerivedKeySize() + NONCE_PREFIX_IN_BYTES + TAG_SIZE_IN_BYTES + 2) {
      throw new GeneralSecurityException(
          "ciphertext_segment_size must be at least (derived_key_size + NONCE_PREFIX_IN_BYTES + "
              + "TAG_SIZE_IN_BYTES + 2)");
    }
  }

  @Override
  public String getKeyType() {
    return TYPE_URL;
  }

  @Override
  public Class<StreamingAead> getPrimitiveClass() {
    return StreamingAead.class;
  }

  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    throw new UnsupportedOperationException("not needed for tests");
  }

  static void register() throws GeneralSecurityException {
    Registry.registerKeyManager(new LegacyAesGcmHkdfStreamingTestKeyManager(), true);
  }
}
