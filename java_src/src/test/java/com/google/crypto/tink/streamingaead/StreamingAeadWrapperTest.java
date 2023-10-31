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

package com.google.crypto.tink.streamingaead;

import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.testing.StreamingTestUtil;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.io.IOException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for StreamingAeadWrapper. */
@RunWith(JUnit4.class)
// Fully specifying proto key/parameters types to distinguish from the programmatic ones.
@SuppressWarnings("UnnecessarilyFullyQualified")
public class StreamingAeadWrapperTest {
  private static final String AES_GCM_HKDF_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey";

  @BeforeClass
  public static void setUp() throws Exception {
    StreamingAeadConfig.register();
  }

  @Test
  public void encryptDecrypt_works() throws Exception {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(32)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacTagSizeBytes(16)
            .setCiphertextSegmentSizeBytes(64)
            .build();
    AesCtrHmacStreamingKey key =
        AesCtrHmacStreamingKey.create(
            parameters,
            SecretBytes.copyFrom(
                Hex.decode("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"),
                InsecureSecretKeyAccess.get()));
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(42).makePrimary())
            .build();

    StreamingAead streamingAead = keysetHandle.getPrimitive(StreamingAead.class);

    StreamingTestUtil.testEncryptDecrypt(streamingAead, 0, 20, 5);
  }

  @Test
  public void encryptDecrypt_usesPrimary() throws Exception {
    AesGcmHkdfStreamingParameters aesGcmHkdfStreamingParameters =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(32)
            .setDerivedAesGcmKeySizeBytes(32)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(64)
            .build();
    AesGcmHkdfStreamingKey aesGcmHkdfStreamingKey =
        AesGcmHkdfStreamingKey.create(
            aesGcmHkdfStreamingParameters,
            SecretBytes.copyFrom(
                Hex.decode("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"),
                InsecureSecretKeyAccess.get()));
    AesCtrHmacStreamingParameters aesCtrHmacStreamingParameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(32)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacTagSizeBytes(16)
            .setCiphertextSegmentSizeBytes(64)
            .build();
    AesCtrHmacStreamingKey aesCtrHmacStreamingKey =
        AesCtrHmacStreamingKey.create(
            aesCtrHmacStreamingParameters,
            SecretBytes.copyFrom(
                Hex.decode("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"),
                InsecureSecretKeyAccess.get()));
    KeysetHandle fullKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(aesCtrHmacStreamingKey).withFixedId(43))
            .addEntry(KeysetHandle.importKey(aesGcmHkdfStreamingKey).withFixedId(42).makePrimary())
            .build();
    KeysetHandle onlyPrimaryKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(aesGcmHkdfStreamingKey).withFixedId(42).makePrimary())
            .build();

    StreamingAead fullStreamingAead = fullKeysetHandle.getPrimitive(StreamingAead.class);
    StreamingAead onlyPrimaryStreamingAead =
        onlyPrimaryKeysetHandle.getPrimitive(StreamingAead.class);

    StreamingTestUtil.testEncryptDecryptDifferentInstances(
        fullStreamingAead, onlyPrimaryStreamingAead, 0, 20, 5);
    StreamingTestUtil.testEncryptDecryptDifferentInstances(
        onlyPrimaryStreamingAead, fullStreamingAead, 0, 20, 5);
  }

  @Test
  public void encryptDecrypt_shiftedPrimaryWorks() throws Exception {
    AesGcmHkdfStreamingParameters aesGcmHkdfStreamingParameters =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(32)
            .setDerivedAesGcmKeySizeBytes(32)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(64)
            .build();
    AesGcmHkdfStreamingKey aesGcmHkdfStreamingKey =
        AesGcmHkdfStreamingKey.create(
            aesGcmHkdfStreamingParameters,
            SecretBytes.copyFrom(
                Hex.decode("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"),
                InsecureSecretKeyAccess.get()));
    AesCtrHmacStreamingParameters aesCtrHmacStreamingParameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(32)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacTagSizeBytes(16)
            .setCiphertextSegmentSizeBytes(64)
            .build();
    AesCtrHmacStreamingKey aesCtrHmacStreamingKey =
        AesCtrHmacStreamingKey.create(
            aesCtrHmacStreamingParameters,
            SecretBytes.copyFrom(
                Hex.decode("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"),
                InsecureSecretKeyAccess.get()));
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(aesCtrHmacStreamingKey).withFixedId(43))
            .addEntry(KeysetHandle.importKey(aesGcmHkdfStreamingKey).withFixedId(42).makePrimary())
            .build();
    KeysetHandle shiftedPrimaryKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(aesCtrHmacStreamingKey).withFixedId(43).makePrimary())
            .addEntry(KeysetHandle.importKey(aesGcmHkdfStreamingKey).withFixedId(42))
            .build();

    StreamingAead streamingAead = keysetHandle.getPrimitive(StreamingAead.class);
    StreamingAead shiftedPrimaryStreamingAead =
        shiftedPrimaryKeysetHandle.getPrimitive(StreamingAead.class);

    StreamingTestUtil.testEncryptDecryptDifferentInstances(
        streamingAead, shiftedPrimaryStreamingAead, 0, 20, 5);
    StreamingTestUtil.testEncryptDecryptDifferentInstances(
        shiftedPrimaryStreamingAead, streamingAead, 0, 20, 5);
  }

  @Test
  public void wrongKey_throws() throws Exception {
    AesGcmHkdfStreamingParameters aesGcmHkdfStreamingParameters =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(32)
            .setDerivedAesGcmKeySizeBytes(32)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(64)
            .build();
    AesGcmHkdfStreamingKey aesGcmHkdfStreamingKey =
        AesGcmHkdfStreamingKey.create(
            aesGcmHkdfStreamingParameters,
            SecretBytes.copyFrom(
                Hex.decode("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"),
                InsecureSecretKeyAccess.get()));
    AesCtrHmacStreamingParameters aesCtrHmacStreamingParameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(32)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacTagSizeBytes(16)
            .setCiphertextSegmentSizeBytes(64)
            .build();
    AesCtrHmacStreamingKey aesCtrHmacStreamingKey =
        AesCtrHmacStreamingKey.create(
            aesCtrHmacStreamingParameters,
            SecretBytes.copyFrom(
                Hex.decode("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"),
                InsecureSecretKeyAccess.get()));
    KeysetHandle aesCtrHmacKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(aesCtrHmacStreamingKey).withFixedId(43).makePrimary())
            .build();
    KeysetHandle aesGcmHkdfKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(aesGcmHkdfStreamingKey).withFixedId(42).makePrimary())
            .build();

    StreamingAead aesCtrHmac = aesCtrHmacKeysetHandle.getPrimitive(StreamingAead.class);
    StreamingAead aesGcmHkdf = aesGcmHkdfKeysetHandle.getPrimitive(StreamingAead.class);

    assertThrows(
        IOException.class,
        () ->
            StreamingTestUtil.testEncryptDecryptDifferentInstances(
                aesCtrHmac, aesGcmHkdf, 0, 20, 5));
    assertThrows(
        IOException.class,
        () ->
            StreamingTestUtil.testEncryptDecryptDifferentInstances(
                aesGcmHkdf, aesCtrHmac, 0, 20, 5));
  }

  @Test
  public void testEncryptDecryptWithTinkKey() throws Exception {
    com.google.crypto.tink.proto.AesGcmHkdfStreamingKey protoKey1 =
        com.google.crypto.tink.proto.AesGcmHkdfStreamingKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFromUtf8("0123456789012345"))
            .setParams(
                com.google.crypto.tink.proto.AesGcmHkdfStreamingParams.newBuilder()
                    .setHkdfHashType(HashType.SHA1)
                    .setDerivedKeySize(16)
                    .setCiphertextSegmentSize(512 * 1024))
            .build();
    Keyset.Key keysetKey1 =
        Keyset.Key.newBuilder()
            .setKeyData(
                KeyData.newBuilder()
                    .setTypeUrl(AES_GCM_HKDF_TYPE_URL)
                    .setValue(protoKey1.toByteString())
                    .setKeyMaterialType(KeyMaterialType.SYMMETRIC))
            .setKeyId(1)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .setStatus(KeyStatusType.ENABLED)
            .build();
    com.google.crypto.tink.proto.AesGcmHkdfStreamingKey protoKey2 =
        com.google.crypto.tink.proto.AesGcmHkdfStreamingKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFromUtf8("0123456789abcdef"))
            .setParams(
                com.google.crypto.tink.proto.AesGcmHkdfStreamingParams.newBuilder()
                    .setHkdfHashType(HashType.SHA1)
                    .setDerivedKeySize(16)
                    .setCiphertextSegmentSize(512 * 1024))
            .build();
    Keyset.Key keysetKey2 =
        Keyset.Key.newBuilder()
            .setKeyData(
                KeyData.newBuilder()
                    .setTypeUrl(AES_GCM_HKDF_TYPE_URL)
                    .setValue(protoKey2.toByteString())
                    .setKeyMaterialType(KeyMaterialType.SYMMETRIC))
            .setKeyId(2)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .setStatus(KeyStatusType.ENABLED)
            .build();

    Keyset keyset =
        Keyset.newBuilder().addKey(keysetKey1).addKey(keysetKey2).setPrimaryKeyId(1).build();
    KeysetHandle keysetHandle =
        TinkProtoKeysetFormat.parseKeyset(keyset.toByteArray(), InsecureSecretKeyAccess.get());
    StreamingAead streamingAead = keysetHandle.getPrimitive(StreamingAead.class);

    StreamingTestUtil.testEncryptionAndDecryption(streamingAead, streamingAead);
  }
}
