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

package com.google.cloud.crypto.tink;

import com.google.cloud.crypto.tink.AesCtrProto.AesCtrKey;
import com.google.cloud.crypto.tink.AesCtrProto.AesCtrParams;
import com.google.cloud.crypto.tink.AesCtrHmacAeadProto.AesCtrHmacAeadKey;
import com.google.cloud.crypto.tink.AesCtrHmacAeadProto.AesCtrHmacAeadParams;
import com.google.cloud.crypto.tink.CommonProto.HashType;
import com.google.cloud.crypto.tink.GoogleCloudKmsProto.GoogleCloudKmsAeadKey;
import com.google.cloud.crypto.tink.HmacProto.HmacKey;
import com.google.cloud.crypto.tink.HmacProto.HmacParams;
import com.google.cloud.crypto.tink.TinkProto.KeyFormat;
import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import com.google.cloud.crypto.tink.TinkProto.Keyset;
import com.google.cloud.crypto.tink.TinkProto.Keyset.Key;
import com.google.cloud.crypto.tink.TinkProto.OutputPrefixType;
import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import com.google.protobuf.Message;
import com.google.protobuf.TextFormat;
import java.security.GeneralSecurityException;
import java.util.concurrent.Future;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Test helpers.
 */
@RunWith(JUnit4.class)
public class TestUtil {
  public static class DummyMac implements Mac {
    public DummyMac() {}
    @Override
    public byte[] computeMac(byte[] data) throws GeneralSecurityException {
      return data;
    }
    @Override
    public boolean verifyMac(byte[] mac, byte[] data) throws GeneralSecurityException {
      return true;
    }
  }

  /**
   * A key manager for DummyMac keys.
   */
  public static class DummyMacKeyManager implements KeyManager<Mac> {
    public DummyMacKeyManager() {}

    @Override
    public Mac getPrimitive(Any proto) throws GeneralSecurityException {
      return new DummyMac();
    }
    @Override
    public Any newKey(KeyFormat format) throws GeneralSecurityException {
      return Any.newBuilder().setTypeUrl(this.getClass().getSimpleName()).build();
    }
    @Override
    public boolean doesSupport(String typeUrl) {
      return typeUrl.equals(this.getClass().getSimpleName());
    }
  }

  public static class EchoAead implements Aead {
    public EchoAead() {}

    @Override
    public byte[] encrypt(byte[] plaintext, byte[] aad) throws GeneralSecurityException {
      return plaintext;
    }
    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] aad) throws GeneralSecurityException {
      return ciphertext;
    }
    @Override
    public Future<byte[]> asyncEncrypt(byte[] plaintext, byte[] aad)
        throws GeneralSecurityException {
      return null;
    }
    @Override
    public Future<byte[]> asyncDecrypt(byte[] ciphertext, byte[] aad)
        throws GeneralSecurityException {
      return null;
    }
  }

  /**
   * A key manager for EchoAead keys that just echo plaintext.
   */
  public static class EchoAeadKeyManager implements KeyManager<Aead> {
    public EchoAeadKeyManager() {}

    @Override
    public Aead getPrimitive(Any proto) throws GeneralSecurityException {
      return new EchoAead();
    }
    @Override
    public Any newKey(KeyFormat format) throws GeneralSecurityException {
      return Any.newBuilder().setTypeUrl(this.getClass().getSimpleName()).build();
    }
    @Override
    public boolean doesSupport(String typeUrl) {
      return typeUrl.equals(this.getClass().getSimpleName());
    }
  }

  public static class FaultyAead implements Aead {
    public FaultyAead() {}

    @Override
    public byte[] encrypt(byte[] plaintext, byte[] aad) throws GeneralSecurityException {
      return new byte[0];
    }
    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] aad) throws GeneralSecurityException {
      return new byte[0];
    }
    @Override
    public Future<byte[]> asyncEncrypt(byte[] plaintext, byte[] aad)
        throws GeneralSecurityException {
      return null;
    }
    @Override
    public Future<byte[]> asyncDecrypt(byte[] ciphertext, byte[] aad)
        throws GeneralSecurityException {
      return null;
    }
  }

  /**
   * A key manager for FaultyAead keys that always return an empty byte array on all encrypt or
   * decrypt requests.
   */
  public static class FaultyAeadKeyManager implements KeyManager<Aead> {
    public FaultyAeadKeyManager() {}

    @Override
    public Aead getPrimitive(Any proto) throws GeneralSecurityException {
      return new FaultyAead();
    }
    @Override
    public Any newKey(KeyFormat format) throws GeneralSecurityException {
      return Any.newBuilder().setTypeUrl(this.getClass().getSimpleName()).build();
    }
    @Override
    public boolean doesSupport(String typeUrl) {
      return typeUrl.equals(this.getClass().getSimpleName());
    }
  }

  /**
   * @returns a keyset from a list of keys. The first key is primary.
   */
  public static Keyset createKeyset(Key primary, Key... keys) throws Exception {
    Keyset.Builder builder = Keyset.newBuilder();
    builder.addKey(primary)
        .setPrimaryKeyId(primary.getKeyId());
    for (Key key : keys) {
      builder.addKey(key);
    }
    return builder.build();
  }

  /**
   * @returns a key with some specific properties.
   */
  public static Key createKey(Message proto, int keyId, KeyStatusType status,
      OutputPrefixType prefixType) throws Exception {
    return Key.newBuilder()
        .setKeyData(Any.pack(proto))
        .setStatus(status)
        .setKeyId(keyId)
        .setOutputPrefixType(prefixType)
        .build();
  }

  /**
   * @returns a {@code HmacKey}.
   */
  public static HmacKey createHmacKey(String keyValue, int tagSize) throws Exception {
    HmacParams params = HmacParams.newBuilder()
        .setHash(HashType.SHA256)
        .setTagSize(tagSize)
        .build();

    return HmacKey.newBuilder()
        .setParams(params)
        .setKeyValue(ByteString.copyFromUtf8(keyValue))
        .build();
  }

  /**
   * @returns a {@code AesCtrKey}.
   */
  public static AesCtrKey createAesCtrKey(String keyValue, int ivSize) throws Exception {
    AesCtrParams aesCtrParams = AesCtrParams.newBuilder()
        .setIvSize(ivSize)
        .build();
    return AesCtrKey.newBuilder()
        .setParams(aesCtrParams)
        .setKeyValue(ByteString.copyFromUtf8(keyValue))
        .build();
  }

  /**
   * @returns a {@code AesCtrHmacAeadKey}.
   */
  public static AesCtrHmacAeadKey createAesCtrHmacAeadKey(String aesCtrKeyValue, int ivSize,
      String hmacKeyValue, int tagSize) throws Exception {
    AesCtrKey aesCtrKey = createAesCtrKey(aesCtrKeyValue, ivSize);
    HmacKey hmacKey = createHmacKey(hmacKeyValue, tagSize);

    return AesCtrHmacAeadKey.newBuilder()
        .setAesCtrKey(aesCtrKey)
        .setHmacKey(hmacKey)
        .build();
  }

  /**
   * @returns a {@code GoogleCloudKmsAeadKey}.
   */
  public static GoogleCloudKmsAeadKey createGoogleCloudKmsAeadKey(String kmsKeyUri)
      throws Exception {
    return GoogleCloudKmsAeadKey.newBuilder()
        .setKmsKeyUri(kmsKeyUri)
        .build();
  }

  /**
   * @returns a KMS key URI in a format defined by Google Cloud KMS.
   */
  public static String createGoogleCloudKmsKeyUri(
    String projectId, String location, String ringId, String keyId) {
    return String.format(
        "projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
        projectId, location, ringId, keyId);
  }

  /**
   * @returns a keyset handle from a {@code keyset}.
   */
  public static KeysetHandle createKeysetHandle(final Keyset keyset) throws Exception {
    return new KeysetHandle(keyset);
  }

  /**
   * @returns a keyset handle from a {@code keyset} which must be a Keyset proto in text format.
   */
  public static KeysetHandle createKeysetHandle(final String keyset) throws Exception {
    try {
      Keyset.Builder keysetBuilder = Keyset.newBuilder();
      TextFormat.merge(keyset, keysetBuilder);
      return createKeysetHandle(keysetBuilder.build());
    } catch (Exception e) {
      System.out.println(e);
      return null;
    }
  }
}
