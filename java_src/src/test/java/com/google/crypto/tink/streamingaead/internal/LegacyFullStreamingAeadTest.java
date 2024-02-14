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

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingParams;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingParameters;
import com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingParameters.HashType;
import com.google.crypto.tink.streamingaead.StreamingAeadConfig;
import com.google.crypto.tink.subtle.AesGcmHkdfStreaming;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.testing.StreamingTestUtil;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
@AccessesPartialKey
public class LegacyFullStreamingAeadTest {
  /** Type url that LegacyFullStreamingAeadIntegration supports. */
  public static final String TYPE_URL = "type.googleapis.com/custom.AesGcmHkdfStreamingKey";

  @Theory
  public void createdPrimitive_encryptDecrypt_works() throws Exception {
    // Set up.
    StreamingAeadConfig.register();
    LegacyAesGcmHkdfStreamingTestKeyManager.register();

    // Create a standard Tink StreamingAead object.
    AesGcmHkdfStreamingKey tinkKey =
        AesGcmHkdfStreamingKey.create(
            AesGcmHkdfStreamingParameters.builder()
                .setHkdfHashType(HashType.SHA256)
                .setKeySizeBytes(32)
                .setDerivedAesGcmKeySizeBytes(16)
                .setCiphertextSegmentSizeBytes(100)
                .build(),
            SecretBytes.copyFrom(
                Hex.decode("000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff"),
                InsecureSecretKeyAccess.get()));
    StreamingAead tinkStreamingAead = AesGcmHkdfStreaming.create(tinkKey);

    // Create a legacy "custom" StreamingAead object.
    AesGcmHkdfStreamingParams params =
        AesGcmHkdfStreamingParams.newBuilder()
            .setHkdfHashType(com.google.crypto.tink.proto.HashType.SHA256)
            .setDerivedKeySize(16)
            .setCiphertextSegmentSize(100)
            .build();
    com.google.crypto.tink.proto.AesGcmHkdfStreamingKey protoKey =
        com.google.crypto.tink.proto.AesGcmHkdfStreamingKey.newBuilder()
            .setKeyValue(
                ByteString.copyFrom(
                    Hex.decode("000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff")))
            .setParams(params)
            .build();
    StreamingAead legacyStreamingAead =
        LegacyFullStreamingAead.create(
            new LegacyProtoKey(
                ProtoKeySerialization.create(
                    TYPE_URL,
                    protoKey.toByteString(),
                    KeyMaterialType.SYMMETRIC,
                    OutputPrefixType.RAW,
                    null),
                InsecureSecretKeyAccess.get()));

    StreamingTestUtil.testEncryptDecryptDifferentInstances(
        tinkStreamingAead, legacyStreamingAead, 0, 20, 20);
    StreamingTestUtil.testEncryptDecryptDifferentInstances(
        legacyStreamingAead, tinkStreamingAead, 0, 20, 20);
  }
}
