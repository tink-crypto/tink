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

import com.google.crypto.tink.KeyManagerBase;
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
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/**
 * This key manager generates new {@code AesGcmHkdfStreamingKey} keys and produces new instances of
 * {@code AesGcmHkdfStreaming}.
 */
class AesGcmHkdfStreamingKeyManager
    extends KeyManagerBase<StreamingAead, AesGcmHkdfStreamingKey, AesGcmHkdfStreamingKeyFormat> {
  public AesGcmHkdfStreamingKeyManager() {
    super(
        StreamingAead.class,
        AesGcmHkdfStreamingKey.class,
        AesGcmHkdfStreamingKeyFormat.class,
        TYPE_URL);
  }

  private static final int VERSION = 0;

  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey";

  /** @param serializedKey serialized {@code AesGcmHkdfStreamingKey} proto */
  @Override
  public StreamingAead getPrimitiveFromKey(AesGcmHkdfStreamingKey keyProto)
      throws GeneralSecurityException {
    return new AesGcmHkdfStreaming(
        keyProto.getKeyValue().toByteArray(),
        StreamingAeadUtil.toHmacAlgo(
            keyProto.getParams().getHkdfHashType()),
        keyProto.getParams().getDerivedKeySize(),
        keyProto.getParams().getCiphertextSegmentSize(),
        /* firstSegmentOffset= */ 0);
  }

  /**
   * @param serializedKeyFormat serialized {@code AesGcmHkdfStreamingKeyFormat} proto
   * @return new {@code AesGcmHkdfStreamingKey} proto
   */
  @Override
  public AesGcmHkdfStreamingKey newKeyFromFormat(AesGcmHkdfStreamingKeyFormat format)
      throws GeneralSecurityException {
    return AesGcmHkdfStreamingKey.newBuilder()
        .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
        .setParams(format.getParams())
        .setVersion(VERSION)
        .build();
  }

  @Override
  public int getVersion() {
    return VERSION;
  }

  @Override
  protected KeyMaterialType keyMaterialType() {
    return KeyMaterialType.SYMMETRIC;
  }

  @Override
  protected AesGcmHkdfStreamingKey parseKeyProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return AesGcmHkdfStreamingKey.parseFrom(byteString);
  }

  @Override
  protected AesGcmHkdfStreamingKeyFormat parseKeyFormatProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return AesGcmHkdfStreamingKeyFormat.parseFrom(byteString);
  }

  @Override
  protected void validateKey(AesGcmHkdfStreamingKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), VERSION);
    validate(key.getParams());
  }

  @Override
  protected void validateKeyFormat(AesGcmHkdfStreamingKeyFormat format)
      throws GeneralSecurityException {
    if (format.getKeySize() < 16) {
      throw new GeneralSecurityException("key_size must be at least 16 bytes");
    }
    validate(format.getParams());
  }

  private void validate(AesGcmHkdfStreamingParams params) throws GeneralSecurityException {
    Validators.validateAesKeySize(params.getDerivedKeySize());
    if (params.getHkdfHashType() == HashType.UNKNOWN_HASH) {
      throw new GeneralSecurityException("unknown HKDF hash type");
    }
    if (params.getCiphertextSegmentSize() < params.getDerivedKeySize() + 8) {
      throw new GeneralSecurityException(
          "ciphertext_segment_size must be at least (derived_key_size + 8)");
    }
  }
}
