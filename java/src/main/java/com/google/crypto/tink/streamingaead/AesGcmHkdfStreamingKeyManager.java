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
import com.google.crypto.tink.proto.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingKeyFormat;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.AesGcmHkdfStreaming;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;

/**
 * This key manager generates new {@code AesGcmHkdfStreamingKey} keys and produces new instances of
 * {@code AesGcmHkdfStreaming}.
 */
public class AesGcmHkdfStreamingKeyManager extends KeyTypeManager<AesGcmHkdfStreamingKey> {
  AesGcmHkdfStreamingKeyManager() {
    super(
        AesGcmHkdfStreamingKey.class,
        new PrimitiveFactory<StreamingAead, AesGcmHkdfStreamingKey>(StreamingAead.class) {
          @Override
          public StreamingAead getPrimitive(AesGcmHkdfStreamingKey key)
              throws GeneralSecurityException {
            return new AesGcmHkdfStreaming(
                key.getKeyValue().toByteArray(),
                StreamingAeadUtil.toHmacAlgo(key.getParams().getHkdfHashType()),
                key.getParams().getDerivedKeySize(),
                key.getParams().getCiphertextSegmentSize(),
                /* firstSegmentOffset= */ 0);
          }
        });
  }

  private static final int NONCE_PREFIX_IN_BYTES = 7;
  private static final int TAG_SIZE_IN_BYTES = 16;

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey";
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
  public void validateKey(AesGcmHkdfStreamingKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), getVersion());
    validateParams(key.getParams());
  }

  @Override
  public AesGcmHkdfStreamingKey parseKey(ByteString byteString)
      throws InvalidProtocolBufferException {
    return AesGcmHkdfStreamingKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public KeyFactory<AesGcmHkdfStreamingKeyFormat, AesGcmHkdfStreamingKey> keyFactory() {
    return new KeyFactory<AesGcmHkdfStreamingKeyFormat, AesGcmHkdfStreamingKey>(
        AesGcmHkdfStreamingKeyFormat.class) {
      @Override
      public void validateKeyFormat(AesGcmHkdfStreamingKeyFormat format)
          throws GeneralSecurityException {
        if (format.getKeySize() < 16) {
          throw new GeneralSecurityException("key_size must be at least 16 bytes");
        }
        validateParams(format.getParams());
      }

      @Override
      public AesGcmHkdfStreamingKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return AesGcmHkdfStreamingKeyFormat.parseFrom(
            byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public AesGcmHkdfStreamingKey createKey(AesGcmHkdfStreamingKeyFormat format)
          throws GeneralSecurityException {
        return AesGcmHkdfStreamingKey.newBuilder()
            .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
            .setParams(format.getParams())
            .setVersion(getVersion())
            .build();
      }

      @Override
      public AesGcmHkdfStreamingKey deriveKey(
          AesGcmHkdfStreamingKeyFormat format, InputStream inputStream)
          throws GeneralSecurityException {
        Validators.validateVersion(format.getVersion(), getVersion());
        byte[] pseudorandomness = new byte[format.getKeySize()];
        try {
          int read = inputStream.read(pseudorandomness);
          if (read != format.getKeySize()) {
            throw new GeneralSecurityException("Not enough pseudorandomness given");
          }
          return AesGcmHkdfStreamingKey.newBuilder()
              .setKeyValue(ByteString.copyFrom(pseudorandomness))
              .setParams(format.getParams())
              .setVersion(getVersion())
              .build();
        } catch (IOException e) {
          throw new GeneralSecurityException("Reading pseudorandomness failed", e);
        }
      }
    };
  }

  private static void validateParams(AesGcmHkdfStreamingParams params)
      throws GeneralSecurityException {
    Validators.validateAesKeySize(params.getDerivedKeySize());
    if (params.getHkdfHashType() == HashType.UNKNOWN_HASH) {
      throw new GeneralSecurityException("unknown HKDF hash type");
    }
    if (params.getCiphertextSegmentSize()
        < params.getDerivedKeySize() + NONCE_PREFIX_IN_BYTES + TAG_SIZE_IN_BYTES + 2) {
      throw new GeneralSecurityException(
          "ciphertext_segment_size must be at least (derived_key_size + NONCE_PREFIX_IN_BYTES + "
              + "TAG_SIZE_IN_BYTES + 2)");
    }
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerKeyManager(new AesGcmHkdfStreamingKeyManager(), newKeyAllowed);
  }
}
