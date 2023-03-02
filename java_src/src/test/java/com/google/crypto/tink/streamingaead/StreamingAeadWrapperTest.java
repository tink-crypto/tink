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

import static com.google.crypto.tink.testing.TestUtil.assertExceptionContains;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.daead.DeterministicAeadConfig;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.Keyset.Key;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.StreamingTestUtil;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ByteString;
import java.io.IOException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for StreamingAeadWrapper. */
@RunWith(JUnit4.class)
public class StreamingAeadWrapperTest {
  private static final int KDF_KEY_SIZE = 16;
  private static final int AES_KEY_SIZE = 16;

  private static final String AES_GCM_HKDF_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey";
  private static final ByteString KEY_BYTES_1 =
      ByteString.copyFromUtf8("0123456789012345");
  private static final ByteString KEY_BYTES_2 =
      ByteString.copyFromUtf8("0123456789abcdef");

  @BeforeClass
  public static void setUp() throws Exception {
    StreamingAeadConfig.register();
    DeterministicAeadConfig.register(); // need this for testInvalidKeyMaterial.
  }

  @Test
  public void testBasicAesCtrHmacStreamingAead() throws Exception {
    byte[] keyValue = Random.randBytes(KDF_KEY_SIZE);
    int derivedKeySize = AES_KEY_SIZE;
    int ciphertextSegmentSize = 128;
    PrimitiveSet<StreamingAead> primitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(
                TestUtil.createKey(
                    TestUtil.createAesCtrHmacStreamingKeyData(
                        keyValue, derivedKeySize, ciphertextSegmentSize),
                    42,
                    KeyStatusType.ENABLED,
                    OutputPrefixType.RAW)),
            StreamingAead.class);
    StreamingAead streamingAead = new StreamingAeadWrapper().wrap(primitives);
    StreamingTestUtil.testEncryptionAndDecryption(streamingAead);
  }

  @Test
  public void testBasicAesGcmHkdfStreamingAead() throws Exception {
    byte[] keyValue = Random.randBytes(KDF_KEY_SIZE);
    int derivedKeySize = AES_KEY_SIZE;
    int ciphertextSegmentSize = 128;
    PrimitiveSet<StreamingAead> primitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(
                TestUtil.createKey(
                    TestUtil.createAesGcmHkdfStreamingKeyData(
                        keyValue, derivedKeySize, ciphertextSegmentSize),
                    42,
                    KeyStatusType.ENABLED,
                    OutputPrefixType.RAW)),
            StreamingAead.class);
    StreamingAead streamingAead = new StreamingAeadWrapper().wrap(primitives);
    StreamingTestUtil.testEncryptionAndDecryption(streamingAead);
  }

  @Test
  public void testMultipleKeys() throws Exception {
    byte[] primaryKeyValue = Random.randBytes(KDF_KEY_SIZE);
    byte[] otherKeyValue = Random.randBytes(KDF_KEY_SIZE);
    byte[] anotherKeyValue = Random.randBytes(KDF_KEY_SIZE);
    int derivedKeySize = AES_KEY_SIZE;

    Key primaryKey =
        TestUtil.createKey(
            TestUtil.createAesGcmHkdfStreamingKeyData(primaryKeyValue, derivedKeySize, 512),
            42,
            KeyStatusType.ENABLED,
            OutputPrefixType.RAW);
    // Another key with a smaller segment size than the primary key
    Key otherKey =
        TestUtil.createKey(
            TestUtil.createAesCtrHmacStreamingKeyData(otherKeyValue, derivedKeySize, 256),
            43,
            KeyStatusType.ENABLED,
            OutputPrefixType.RAW);
    // Another key with a larger segment size than the primary key
    Key anotherKey =
        TestUtil.createKey(
            TestUtil.createAesGcmHkdfStreamingKeyData(anotherKeyValue, derivedKeySize, 1024),
            72,
            KeyStatusType.ENABLED,
            OutputPrefixType.RAW);

    PrimitiveSet<StreamingAead> primitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(primaryKey, otherKey, anotherKey), StreamingAead.class);
    StreamingAead streamingAead = new StreamingAeadWrapper().wrap(primitives);

    StreamingAead primaryAead =
        new StreamingAeadWrapper()
            .wrap(
                TestUtil.createPrimitiveSet(
                    TestUtil.createKeyset(primaryKey), StreamingAead.class));
    StreamingAead otherAead =
        new StreamingAeadWrapper()
            .wrap(
                TestUtil.createPrimitiveSet(TestUtil.createKeyset(otherKey), StreamingAead.class));
    StreamingAead anotherAead =
        new StreamingAeadWrapper()
            .wrap(
                TestUtil.createPrimitiveSet(
                    TestUtil.createKeyset(anotherKey), StreamingAead.class));

    StreamingTestUtil.testEncryptionAndDecryption(streamingAead, streamingAead);
    StreamingTestUtil.testEncryptionAndDecryption(streamingAead, primaryAead);
    StreamingTestUtil.testEncryptionAndDecryption(primaryAead, streamingAead);
    StreamingTestUtil.testEncryptionAndDecryption(otherAead, streamingAead);
    StreamingTestUtil.testEncryptionAndDecryption(anotherAead, streamingAead);
    StreamingTestUtil.testEncryptionAndDecryption(primaryAead, primaryAead);
    StreamingTestUtil.testEncryptionAndDecryption(otherAead, otherAead);
    StreamingTestUtil.testEncryptionAndDecryption(anotherAead, anotherAead);
    IOException expected =
        assertThrows(
            IOException.class,
            () -> StreamingTestUtil.testEncryptionAndDecryption(otherAead, primaryAead));
    assertExceptionContains(expected, "No matching key");
    IOException expected2 =
        assertThrows(
            IOException.class,
            () -> StreamingTestUtil.testEncryptionAndDecryption(anotherAead, primaryAead));
    assertExceptionContains(expected2, "No matching key");
  }

  @Test
  public void testEncryptDecryptWithTinkKey() throws Exception {
    AesGcmHkdfStreamingKey protoKey1 =
        AesGcmHkdfStreamingKey.newBuilder()
            .setVersion(0)
            .setKeyValue(KEY_BYTES_1)
            .setParams(
                AesGcmHkdfStreamingParams.newBuilder()
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
    AesGcmHkdfStreamingKey protoKey2 =
        AesGcmHkdfStreamingKey.newBuilder()
            .setVersion(0)
            .setKeyValue(KEY_BYTES_2)
            .setParams(
                AesGcmHkdfStreamingParams.newBuilder()
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

    // TODO(b/129044084) We need to change Tink so this works.
    assertThrows(
        IOException.class,
        () -> StreamingTestUtil.testEncryptionAndDecryption(streamingAead, streamingAead));
  }
}
