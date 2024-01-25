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

package com.google.crypto.tink.streamingaead;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.streamingaead.internal.LegacyAesGcmHkdfStreamingTestKeyManager;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.testing.StreamingTestUtil;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests that ensure that StreamingAeadWrapper properly handles LegacyFullStreamingAead. */
@RunWith(JUnit4.class)
@AccessesPartialKey
public class StreamingAeadWrapperLegacyTest {
  /** Type url that LegacyFullStreamingAeadIntegration supports. */
  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey";

  @BeforeClass
  public static void setUp() throws Exception {
    StreamingAeadWrapper.register();
    AesCtrHmacStreamingKeyManager.register(true);
    LegacyAesGcmHkdfStreamingTestKeyManager.register();
  }

  @Test
  public void endToEnd_onlyLegacy_works() throws Exception {
    AesGcmHkdfStreamingParams protoParams =
        AesGcmHkdfStreamingParams.newBuilder()
            .setHkdfHashType(HashType.SHA256)
            .setDerivedKeySize(32)
            .setCiphertextSegmentSize(64)
            .build();
    AesGcmHkdfStreamingKey protoKey =
        AesGcmHkdfStreamingKey.newBuilder()
            .setKeyValue(
                ByteString.copyFrom(
                    Hex.decode("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd")))
            .setParams(protoParams)
            .build();
    KeyData keyData =
        KeyData.newBuilder()
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .setTypeUrl(TYPE_URL)
            .setValue(protoKey.toByteString())
            .build();
    Keyset.Key rawKeysetKey =
        Keyset.Key.newBuilder()
            .setKeyData(keyData)
            .setStatus(KeyStatusType.ENABLED)
            .setKeyId(42)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    KeysetHandle keysetHandle =
        TinkProtoKeysetFormat.parseKeyset(
            Keyset.newBuilder().addKey(rawKeysetKey).setPrimaryKeyId(42).build().toByteArray(),
            InsecureSecretKeyAccess.get());

    StreamingAead streamingAead = keysetHandle.getPrimitive(StreamingAead.class);

    // Ensure that the legacy API will be used for AesGcmHkdfStreaming.
    assertThat(
            MutableSerializationRegistry.globalInstance()
                .hasParserForKey(
                    ProtoKeySerialization.create(
                        TYPE_URL,
                        rawKeysetKey.toByteString(),
                        KeyMaterialType.SYMMETRIC,
                        OutputPrefixType.RAW,
                        null)))
        .isFalse();
    StreamingTestUtil.testEncryptDecrypt(streamingAead, 0, 20, 5);
  }

  @Test
  public void endToEnd_legacyAndNewApi_works() throws Exception {
    AesGcmHkdfStreamingParams protoParams =
        AesGcmHkdfStreamingParams.newBuilder()
            .setHkdfHashType(HashType.SHA256)
            .setDerivedKeySize(32)
            .setCiphertextSegmentSize(64)
            .build();
    AesGcmHkdfStreamingKey protoKey =
        AesGcmHkdfStreamingKey.newBuilder()
            .setKeyValue(
                ByteString.copyFrom(
                    Hex.decode("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd")))
            .setParams(protoParams)
            .build();
    KeyData keyData =
        KeyData.newBuilder()
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .setTypeUrl(TYPE_URL)
            .setValue(protoKey.toByteString())
            .build();
    Keyset.Key rawKeysetKey =
        Keyset.Key.newBuilder()
            .setKeyData(keyData)
            .setStatus(KeyStatusType.ENABLED)
            .setKeyId(42)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    KeysetHandle legacyKeysKeysetHandle =
        TinkProtoKeysetFormat.parseKeyset(
            Keyset.newBuilder().addKey(rawKeysetKey).setPrimaryKeyId(42).build().toByteArray(),
            InsecureSecretKeyAccess.get());
    AesCtrHmacStreamingParameters programmaticParams =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(32)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacTagSizeBytes(16)
            .setCiphertextSegmentSizeBytes(64)
            .build();
    AesCtrHmacStreamingKey programmaticKey =
        AesCtrHmacStreamingKey.create(
            programmaticParams,
            SecretBytes.copyFrom(
                Hex.decode("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"),
                InsecureSecretKeyAccess.get()));
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder(legacyKeysKeysetHandle)
            .addEntry(KeysetHandle.importKey(programmaticKey).withFixedId(43))
            .build();

    StreamingAead streamingAead = keysetHandle.getPrimitive(StreamingAead.class);

    // Ensure that the legacy API will be used for AesGcmHkdfStreaming.
    assertThat(
            MutableSerializationRegistry.globalInstance()
                .hasParserForKey(
                    ProtoKeySerialization.create(
                        TYPE_URL,
                        rawKeysetKey.toByteString(),
                        KeyMaterialType.SYMMETRIC,
                        OutputPrefixType.RAW,
                        null)))
        .isFalse();
    StreamingTestUtil.testEncryptDecrypt(streamingAead, 0, 20, 5);
  }
}
