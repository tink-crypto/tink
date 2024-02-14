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

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.streamingaead.StreamingAeadConfig;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.testing.StreamingTestUtil;
import com.google.crypto.tink.testing.StreamingTestUtil.SeekableByteBufferChannel;
import com.google.protobuf.ByteString;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.util.Arrays;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class LegacyFullStreamingAeadIntegrationTest {
  /** Type url that LegacyFullStreamingAeadIntegration supports. */
  public static final String TYPE_URL = "type.googleapis.com/custom.AesGcmHkdfStreamingKey";

  private static KeysetHandle rawKeysetHandle;
  private static KeyData keyData;

  @BeforeClass
  public static void setUp() throws Exception {
    StreamingAeadConfig.register();
    LegacyAesGcmHkdfStreamingTestKeyManager.register();

    AesGcmHkdfStreamingParams params =
        AesGcmHkdfStreamingParams.newBuilder()
            .setHkdfHashType(HashType.SHA256)
            .setDerivedKeySize(32)
            .setCiphertextSegmentSize(64)
            .build();
    AesGcmHkdfStreamingKey key =
        AesGcmHkdfStreamingKey.newBuilder()
            .setKeyValue(
                ByteString.copyFrom(
                    Hex.decode("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd")))
            .setParams(params)
            .build();
    keyData =
        KeyData.newBuilder()
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .setTypeUrl(TYPE_URL)
            .setValue(key.toByteString())
            .build();
    Keyset.Key rawKeysetKey =
        Keyset.Key.newBuilder()
            .setKeyData(keyData)
            .setStatus(KeyStatusType.ENABLED)
            .setKeyId(0x0000002a)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    rawKeysetHandle =
        TinkProtoKeysetFormat.parseKeyset(
            Keyset.newBuilder()
                .addKey(rawKeysetKey)
                .setPrimaryKeyId(0x0000002a)
                .build()
                .toByteArray(),
            InsecureSecretKeyAccess.get());
  }

  @Test
  public void endToEnd_works() throws Exception {
    StreamingAead streamingAead = rawKeysetHandle.getPrimitive(StreamingAead.class);

    assertThat(streamingAead).isNotNull();
  }

  @Test
  public void endToEnd_decryptIsCorrect() throws Exception {
    byte[] associatedData = Hex.decode("abcdef0123456789");
    byte[] ciphertext =
        Hex.decode(
            "2835ef18cf07696f0a3dce18e25c9a26e7ad57a4ad47a9d39aef03a328db5109"
                + "164f6f240a1e9ed9b8d289ec3ddad4c221c0e60b7b143d63231aeeffca384241"
                + "0d19f0613b690ee32796f2a2d3c19fc778");

    StreamingAead streamingAead = rawKeysetHandle.getPrimitive(StreamingAead.class);
    ReadableByteChannel plaintextChannel =
        streamingAead.newDecryptingChannel(
            new SeekableByteBufferChannel(ciphertext), associatedData);
    ByteBuffer plaintext = ByteBuffer.allocate(1024); // a surely long enough buffer
    int read = plaintextChannel.read(plaintext);

    assertThat(read).isEqualTo("plaintext".getBytes(UTF_8).length);
    assertThat(Arrays.copyOf(plaintext.array(), read)).isEqualTo("plaintext".getBytes(UTF_8));
  }

  @Test
  public void endToEnd_encryptDecryptIsCorrect() throws Exception {
    StreamingAead streamingAead = rawKeysetHandle.getPrimitive(StreamingAead.class);

    StreamingTestUtil.testEncryptDecrypt(streamingAead, 0, 20, 20);
  }

  // StreamingAead doesn't work with non-raw keys and doesn't produce prefixed ciphertexts.
  // Tests below ensure that this behaviour is preserved.
  @Test
  public void endToEnd_decryptRejectsPrefixedCiphertextTink() throws Exception {
    byte[] associatedData = Hex.decode("abcdef0123456789");
    byte[] ciphertext =
        Hex.decode(
            "010000002a"
                + "2835ef18cf07696f0a3dce18e25c9a26e7ad57a4ad47a9d39aef03a328db5109"
                + "164f6f240a1e9ed9b8d289ec3ddad4c221c0e60b7b143d63231aeeffca384241"
                + "0d19f0613b690ee32796f2a2d3c19fc778");
    Keyset.Key tinkKeysetKey =
        Keyset.Key.newBuilder()
            .setKeyData(keyData)
            .setStatus(KeyStatusType.ENABLED)
            .setKeyId(0x0000002a)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    KeysetHandle tinkKeysetHandle =
        TinkProtoKeysetFormat.parseKeyset(
            Keyset.newBuilder()
                .addKey(tinkKeysetKey)
                .setPrimaryKeyId(0x0000002a)
                .build()
                .toByteArray(),
            InsecureSecretKeyAccess.get());

    StreamingAead streamingAead = tinkKeysetHandle.getPrimitive(StreamingAead.class);
    ReadableByteChannel plaintextChannel =
        streamingAead.newDecryptingChannel(
            new SeekableByteBufferChannel(ciphertext), associatedData);
    ByteBuffer plaintext = ByteBuffer.allocate(1024); // a surely long enough buffer

    assertThrows(IOException.class, () -> plaintextChannel.read(plaintext));
  }

  @Test
  public void endToEnd_decryptRejectsPrefixedCiphertextCrunchy() throws Exception {
    byte[] associatedData = Hex.decode("abcdef0123456789");
    byte[] ciphertext =
        Hex.decode(
            "000000002a"
                + "2835ef18cf07696f0a3dce18e25c9a26e7ad57a4ad47a9d39aef03a328db5109"
                + "164f6f240a1e9ed9b8d289ec3ddad4c221c0e60b7b143d63231aeeffca384241"
                + "0d19f0613b690ee32796f2a2d3c19fc778");
    Keyset.Key crunchyKeysetKey =
        Keyset.Key.newBuilder()
            .setKeyData(keyData)
            .setStatus(KeyStatusType.ENABLED)
            .setKeyId(0x0000002a)
            .setOutputPrefixType(OutputPrefixType.CRUNCHY)
            .build();
    KeysetHandle crunchyKeysetHandle =
        TinkProtoKeysetFormat.parseKeyset(
            Keyset.newBuilder()
                .addKey(crunchyKeysetKey)
                .setPrimaryKeyId(0x0000002a)
                .build()
                .toByteArray(),
            InsecureSecretKeyAccess.get());

    StreamingAead streamingAead = crunchyKeysetHandle.getPrimitive(StreamingAead.class);
    ReadableByteChannel plaintextChannel =
        streamingAead.newDecryptingChannel(
            new SeekableByteBufferChannel(ciphertext), associatedData);
    ByteBuffer plaintext = ByteBuffer.allocate(1024); // a surely long enough buffer

    assertThrows(IOException.class, () -> plaintextChannel.read(plaintext));
  }

  @Test
  public void endToEnd_decryptRejectsPrefixedCiphertextLegacy() throws Exception {
    byte[] associatedData = Hex.decode("abcdef0123456789");
    byte[] ciphertext =
        Hex.decode(
            "000000002a"
                + "2835ef18cf07696f0a3dce18e25c9a26e7ad57a4ad47a9d39aef03a328db5109"
                + "164f6f240a1e9ed9b8d289ec3ddad4c221c0e60b7b143d63231aeeffca384241"
                + "0d19f0613b690ee32796f2a2d3c19fc778");
    Keyset.Key legacyKeysetKey =
        Keyset.Key.newBuilder()
            .setKeyData(keyData)
            .setStatus(KeyStatusType.ENABLED)
            .setKeyId(0x0000002a)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();
    KeysetHandle legacyKeysetHandle =
        TinkProtoKeysetFormat.parseKeyset(
            Keyset.newBuilder()
                .addKey(legacyKeysetKey)
                .setPrimaryKeyId(0x0000002a)
                .build()
                .toByteArray(),
            InsecureSecretKeyAccess.get());

    StreamingAead streamingAead = legacyKeysetHandle.getPrimitive(StreamingAead.class);
    ReadableByteChannel plaintextChannel =
        streamingAead.newDecryptingChannel(
            new SeekableByteBufferChannel(ciphertext), associatedData);
    ByteBuffer plaintext = ByteBuffer.allocate(1024); // a surely long enough buffer

    assertThrows(IOException.class, () -> plaintextChannel.read(plaintext));
  }
}
