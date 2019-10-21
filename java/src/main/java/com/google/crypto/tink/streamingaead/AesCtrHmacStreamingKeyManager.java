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
// //////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.streamingaead;

import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.proto.AesCtrHmacStreamingKey;
import com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat;
import com.google.crypto.tink.proto.AesCtrHmacStreamingParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.AesCtrHmacStreaming;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/**
 * This key manager generates new {@code AesCtrHmacStreamingKey} keys and produces new instances of
 * {@code AesCtrHmacStreaming}.
 */
public class AesCtrHmacStreamingKeyManager extends KeyTypeManager<AesCtrHmacStreamingKey> {
  AesCtrHmacStreamingKeyManager() {
    super(
        AesCtrHmacStreamingKey.class,
        new PrimitiveFactory<StreamingAead, AesCtrHmacStreamingKey>(StreamingAead.class) {
          @Override
          public StreamingAead getPrimitive(AesCtrHmacStreamingKey key)
              throws GeneralSecurityException {
            return new AesCtrHmacStreaming(
                key.getKeyValue().toByteArray(),
                StreamingAeadUtil.toHmacAlgo(key.getParams().getHkdfHashType()),
                key.getParams().getDerivedKeySize(),
                StreamingAeadUtil.toHmacAlgo(key.getParams().getHmacParams().getHash()),
                key.getParams().getHmacParams().getTagSize(),
                key.getParams().getCiphertextSegmentSize(),
                /* firstSegmentOffset= */ 0);
          }
        });
  }

  /** Minimum tag size in bytes. This provides minimum 80-bit security strength. */
  private static final int MIN_TAG_SIZE_IN_BYTES = 10;

  private static final int NONCE_PREFIX_IN_BYTES = 7;

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey";
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.SYMMETRIC;
  }

  @Override
  public void validateKey(AesCtrHmacStreamingKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), getVersion());
    if (key.getKeyValue().size() < 16) {
      throw new GeneralSecurityException("key_value must have at least 16 bytes");
    }
    if (key.getKeyValue().size() < key.getParams().getDerivedKeySize()) {
      throw new GeneralSecurityException(
          "key_value must have at least as many bits as derived keys");
    }
    validateParams(key.getParams());
  }

  @Override
  public AesCtrHmacStreamingKey parseKey(ByteString byteString)
      throws InvalidProtocolBufferException {
    return AesCtrHmacStreamingKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public KeyFactory<AesCtrHmacStreamingKeyFormat, AesCtrHmacStreamingKey> keyFactory() {
    return new KeyFactory<AesCtrHmacStreamingKeyFormat, AesCtrHmacStreamingKey>(
        AesCtrHmacStreamingKeyFormat.class) {
      @Override
      public void validateKeyFormat(AesCtrHmacStreamingKeyFormat format)
          throws GeneralSecurityException {
        if (format.getKeySize() < 16) {
          throw new GeneralSecurityException("key_size must be at least 16 bytes");
        }
        validateParams(format.getParams());
      }

      @Override
      public AesCtrHmacStreamingKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return AesCtrHmacStreamingKeyFormat.parseFrom(
            byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public AesCtrHmacStreamingKey createKey(AesCtrHmacStreamingKeyFormat format)
          throws GeneralSecurityException {
        return AesCtrHmacStreamingKey.newBuilder()
            .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
            .setParams(format.getParams())
            .setVersion(getVersion())
            .build();
      }
    };
  }

  private static void validateParams(AesCtrHmacStreamingParams params)
      throws GeneralSecurityException {
    Validators.validateAesKeySize(params.getDerivedKeySize());
    if (params.getHkdfHashType() == HashType.UNKNOWN_HASH) {
      throw new GeneralSecurityException("unknown HKDF hash type");
    }
    if (params.getHmacParams().getHash() == HashType.UNKNOWN_HASH) {
      throw new GeneralSecurityException("unknown HMAC hash type");
    }
    validateHmacParams(params.getHmacParams());

    if (params.getCiphertextSegmentSize()
        < params.getDerivedKeySize()
            + params.getHmacParams().getTagSize()
            + 2
            + NONCE_PREFIX_IN_BYTES) {
      throw new GeneralSecurityException(
          "ciphertext_segment_size must be at least (derived_key_size + tag_size + "
              + "NONCE_PREFIX_IN_BYTES + 2)");
    }
  }

  private static void validateHmacParams(HmacParams params) throws GeneralSecurityException {
    if (params.getTagSize() < MIN_TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("tag size too small");
    }
    switch (params.getHash()) {
      case SHA1:
        if (params.getTagSize() > 20) {
          throw new GeneralSecurityException("tag size too big");
        }
        break;
      case SHA256:
        if (params.getTagSize() > 32) {
          throw new GeneralSecurityException("tag size too big");
        }
        break;
      case SHA512:
        if (params.getTagSize() > 64) {
          throw new GeneralSecurityException("tag size too big");
        }
        break;
      default:
        throw new GeneralSecurityException("unknown hash type");
    }
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerKeyManager(new AesCtrHmacStreamingKeyManager(), newKeyAllowed);
  }
}
