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

import com.google.crypto.tink.Registry;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.AesGcmHkdfStreaming;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.testing.StreamingTestUtil;
import com.google.crypto.tink.testing.StreamingTestUtil.SeekableByteBufferChannel;
import com.google.protobuf.ByteString;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.util.Arrays;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class LegacyAesGcmHkdfStreamingTestKeyManagerTest {
  /** Type url that this manager supports. */
  public static final String TYPE_URL =
      "type.googleapis.com/custom.AesGcmHkdfStreamingKey";

  @BeforeClass
  public static void setUp() throws Exception {
    LegacyAesGcmHkdfStreamingTestKeyManager.register();
  }

  @Test
  public void getPrimitive_works() throws Exception {
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
    KeyData keyData =
        KeyData.newBuilder()
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .setTypeUrl(TYPE_URL)
            .setValue(key.toByteString())
            .build();

    StreamingAead streamingAead = Registry.getPrimitive(keyData, StreamingAead.class);

    assertThat(streamingAead).isNotNull();
    assertThat(streamingAead).isInstanceOf(AesGcmHkdfStreaming.class);
  }

  @Test
  public void getPrimitive_encryptDecrypt_works() throws Exception {
    AesGcmHkdfStreamingParams params =
        AesGcmHkdfStreamingParams.newBuilder()
            .setHkdfHashType(HashType.SHA512)
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
    KeyData keyData =
        KeyData.newBuilder()
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .setTypeUrl(TYPE_URL)
            .setValue(key.toByteString())
            .build();

    StreamingAead streamingAead = Registry.getPrimitive(keyData, StreamingAead.class);

    StreamingTestUtil.testEncryptDecrypt(streamingAead, 0, 20, 5);
  }

  @Test
  public void getPrimitive_decryptWithChannel_works() throws Exception {
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
    KeyData keyData =
        KeyData.newBuilder()
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .setTypeUrl(TYPE_URL)
            .setValue(key.toByteString())
            .build();
    byte[] associatedData = Hex.decode("abcdef0123456789");
    byte[] ciphertext =
        Hex.decode(
            "2835ef18cf07696f0a3dce18e25c9a26e7ad57a4ad47a9d39aef03a328db5109"
                + "164f6f240a1e9ed9b8d289ec3ddad4c221c0e60b7b143d63231aeeffca384241"
                + "0d19f0613b690ee32796f2a2d3c19fc778");

    StreamingAead streamingAead = Registry.getPrimitive(keyData, StreamingAead.class);
    ReadableByteChannel plaintextChannel =
        streamingAead.newDecryptingChannel(
            new SeekableByteBufferChannel(ciphertext), associatedData);
    ByteBuffer plaintext = ByteBuffer.allocate(2 * "plaintext".getBytes(UTF_8).length);
    int read = plaintextChannel.read(plaintext);

    assertThat(read).isEqualTo("plaintext".getBytes(UTF_8).length);
    assertThat(Arrays.copyOf(plaintext.array(), read)).isEqualTo("plaintext".getBytes(UTF_8));
  }

  @Test
  public void getPrimitive_decryptWithStream_works() throws Exception {
    AesGcmHkdfStreamingParams params =
        AesGcmHkdfStreamingParams.newBuilder()
            .setHkdfHashType(HashType.SHA512)
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
    KeyData keyData =
        KeyData.newBuilder()
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .setTypeUrl(TYPE_URL)
            .setValue(key.toByteString())
            .build();
    byte[] associatedData = Hex.decode("abcdef0123456789");
    byte[] ciphertext =
        Hex.decode(
            "28a051f98fe397ed70c7096c6dae34448b9fe0bcd702a061eb4d378149069217"
                + "719ea94ed90e881eb6f881dd3e41342ce894faab9dbfa76077d94f88b5897dfe"
                + "7f8dc971ecef7cdb28c25aa19fbc4be30e");
    InputStream ciphertextStream = new ByteArrayInputStream(ciphertext);

    StreamingAead streamingAead = Registry.getPrimitive(keyData, StreamingAead.class);
    InputStream plaintextStream =
        streamingAead.newDecryptingStream(ciphertextStream, associatedData);
    byte[] plaintext = new byte[2 * "plaintext".getBytes(UTF_8).length];
    int read = plaintextStream.read(plaintext);

    assertThat(read).isEqualTo("plaintext".getBytes(UTF_8).length);
    assertThat(Arrays.copyOf(plaintext, read)).isEqualTo("plaintext".getBytes(UTF_8));
  }
}
