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
import com.google.crypto.tink.PrimitiveWrapper;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveSet;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.testing.StreamingTestUtil;
import com.google.crypto.tink.testing.StreamingTestUtil.SeekableByteBufferChannel;
import com.google.protobuf.ByteString;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class LegacyFullStreamingAeadIntegrationTest {
  /** Type url that LegacyFullStreamingAeadIntegration supports. */
  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey";

  @BeforeClass
  public static void setUp() throws Exception {
    LegacyAesGcmHkdfStreamingTestKeyManager.register();
  }

  /*  Tests that when
   *      1. the LegacyFullStreamingAead is registered
   *  and
   *      2. the LegacyProtoKeys handling StreamingAead are present
   *  then from those keys the LegacyFullStreamingAeads will be created.
   */
  @Test
  public void endToEnd_works() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(
            PrimitiveConstructor.create(
                LegacyFullStreamingAead::create, LegacyProtoKey.class, StreamingAead.class));
    /*  We have to use a test wrapper since we need direct access to the primitive that was passed
     *  to the wrapper. The actual wrapper returns the primitives wrapped into a helper class.
     */
    TestLegacyStreamingAeadWrapper.register();

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

    assertThat(streamingAead).isInstanceOf(LegacyFullStreamingAead.class);
  }

  @Test
  public void endToEnd_decryptIsCorrect() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(
            PrimitiveConstructor.create(
                LegacyFullStreamingAead::create, LegacyProtoKey.class, StreamingAead.class));

    TestLegacyStreamingAeadWrapper.register();

    byte[] associatedData = Hex.decode("abcdef0123456789");
    byte[] ciphertext =
        Hex.decode(
            "2835ef18cf07696f0a3dce18e25c9a26e7ad57a4ad47a9d39aef03a328db5109"
                + "164f6f240a1e9ed9b8d289ec3ddad4c221c0e60b7b143d63231aeeffca384241"
                + "0d19f0613b690ee32796f2a2d3c19fc778");

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
    ReadableByteChannel plaintextChannel =
        streamingAead.newDecryptingChannel(
            new SeekableByteBufferChannel(ciphertext), associatedData);
    ByteBuffer plaintext = ByteBuffer.allocate(2 * "plaintext".getBytes(UTF_8).length);
    int read = plaintextChannel.read(plaintext);

    assertThat(read).isEqualTo("plaintext".getBytes(UTF_8).length);
    assertThat(Arrays.copyOf(plaintext.array(), read)).isEqualTo("plaintext".getBytes(UTF_8));
  }

  @Test
  public void endToEnd_encryptDecryptIsCorrect() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(
            PrimitiveConstructor.create(
                LegacyFullStreamingAead::create, LegacyProtoKey.class, StreamingAead.class));
    TestLegacyStreamingAeadWrapper.register();

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

    StreamingTestUtil.testEncryptDecrypt(streamingAead, 0, 20, 20);
  }

  @Test
  public void legacyFullStreamingAeadNotRegistered_fails() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();

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

    assertThrows(
        GeneralSecurityException.class, () -> keysetHandle.getPrimitive(StreamingAead.class));
  }

  private static final class TestLegacyStreamingAeadWrapper
      implements PrimitiveWrapper<StreamingAead, StreamingAead> {

    static final TestLegacyStreamingAeadWrapper WRAPPER = new TestLegacyStreamingAeadWrapper();

    @Override
    public StreamingAead wrap(PrimitiveSet<StreamingAead> primitiveSet) {
      return primitiveSet.getPrimary().getFullPrimitive();
    }

    @Override
    public Class<StreamingAead> getPrimitiveClass() {
      return StreamingAead.class;
    }

    @Override
    public Class<StreamingAead> getInputPrimitiveClass() {
      return StreamingAead.class;
    }

    static void register() throws GeneralSecurityException {
      MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(WRAPPER);
    }
  }
}
