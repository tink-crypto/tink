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

import static com.google.common.io.BaseEncoding.base16;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.cloud.crypto.tink.AesCtrHmacAeadProto.AesCtrHmacAeadKey;
import com.google.cloud.crypto.tink.AesCtrHmacAeadProto.AesCtrHmacAeadKeyFormat;
import com.google.cloud.crypto.tink.AesCtrProto.AesCtrKey;
import com.google.cloud.crypto.tink.AesCtrProto.AesCtrKeyFormat;
import com.google.cloud.crypto.tink.AesCtrProto.AesCtrParams;
import com.google.cloud.crypto.tink.AesGcmProto.AesGcmKey;
import com.google.cloud.crypto.tink.CommonProto.HashType;
import com.google.cloud.crypto.tink.GoogleCloudKmsProto.GoogleCloudKmsAeadKey;
import com.google.cloud.crypto.tink.HmacProto.HmacKey;
import com.google.cloud.crypto.tink.HmacProto.HmacKeyFormat;
import com.google.cloud.crypto.tink.HmacProto.HmacParams;
import com.google.cloud.crypto.tink.KmsEnvelopeProto.KmsEnvelopeAeadKey;
import com.google.cloud.crypto.tink.KmsEnvelopeProto.KmsEnvelopeAeadParams;
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
   * @return a keyset from a list of keys. The first key is primary.
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
   * @return a key with some specific properties.
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
   * @return a {@code HmacKey}.
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
   * @return a {@code AesCtrKey}.
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
   * @return a {@code AesCtrHmacAeadKey}.
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
   * @return a {@code AesGcmKey}.
   */
  public static AesGcmKey createAesGcmKey(String keyValue) throws Exception {
    return AesGcmKey.newBuilder()
        .setKeyValue(ByteString.copyFromUtf8(keyValue))
        .build();
  }

  /**
   * @return a {@code AesGcmKey}.
   */
  public static AesGcmKey createAesGcmKey(byte[] keyValue) throws Exception {
    return AesGcmKey.newBuilder()
        .setKeyValue(ByteString.copyFrom(keyValue))
        .build();
  }

  /**
   * @return a {@code AesCtrHmacAeadKeyFormat}.
   */
  public static KeyFormat createAesCtrHmacAeadKeyFormat(int aesKeySize, int ivSize,
      int hmacKeySize, int tagSize) throws Exception {
    AesCtrKeyFormat aesCtrKeyFormat = AesCtrKeyFormat.newBuilder()
        .setParams(AesCtrParams.newBuilder().setIvSize(ivSize).build())
        .setKeySize(aesKeySize)
        .build();
    HmacKeyFormat hmacKeyFormat = HmacKeyFormat.newBuilder()
        .setParams(
            HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(tagSize).build())
        .setKeySize(hmacKeySize)
        .build();
    AesCtrHmacAeadKeyFormat format = AesCtrHmacAeadKeyFormat.newBuilder()
        .setAesCtrKeyFormat(aesCtrKeyFormat)
        .setHmacKeyFormat(hmacKeyFormat)
        .build();
    return KeyFormat.newBuilder()
        .setFormat(Any.pack(format))
        .setKeyType("type.googleapis.com/google.cloud.crypto.tink.AesCtrHmacAeadKey")
        .build();
  }

  /**
   * @return a {@code GoogleCloudKmsAeadKey}.
   */
  public static GoogleCloudKmsAeadKey createGoogleCloudKmsAeadKey(String kmsKeyUri)
      throws Exception {
    return GoogleCloudKmsAeadKey.newBuilder()
        .setKmsKeyUri(kmsKeyUri)
        .build();
  }

  /**
   * @return a {@code KmsEnvelopeAeadKey}.
   */
  public static KmsEnvelopeAeadKey createKmsEnvelopeAeadKey(Any kmsKey, KeyFormat dekFormat)
      throws Exception {
    KmsEnvelopeAeadParams params = KmsEnvelopeAeadParams.newBuilder()
        .setDekFormat(dekFormat)
        .setKmsKey(kmsKey)
        .build();
    return KmsEnvelopeAeadKey.newBuilder().setParams(params).build();
  }

  /**
   * @return a KMS key URI in a format defined by Google Cloud KMS.
   */
  public static String createGoogleCloudKmsKeyUri(
    String projectId, String location, String ringId, String keyId) {
    return String.format(
        "projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
        projectId, location, ringId, keyId);
  }

  /**
   * @return a keyset handle from a {@code keyset}.
   */
  public static KeysetHandle createKeysetHandle(final Keyset keyset) throws Exception {
    return new KeysetHandle(keyset);
  }

  /**
   * @return a keyset handle from a {@code keyset} which must be a Keyset proto in text format.
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

  /**
   * Runs basic tests against an Aead primitive.
   */
  public static void runBasicTests(Aead aead) throws Exception {
    byte[] plaintext = "plaintext".getBytes("UTF-8");
    byte[] associatedData = "associatedData".getBytes("UTF-8");
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);

    byte original = ciphertext[0];
    ciphertext[0] = (byte) ~original;
    try {
      aead.decrypt(ciphertext, associatedData);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("decrypted failed"));
    }

    ciphertext[0] = original;
    original = ciphertext[CryptoFormat.NON_RAW_PREFIX_SIZE];
    ciphertext[CryptoFormat.NON_RAW_PREFIX_SIZE] = (byte) ~original;
    try {
      aead.decrypt(ciphertext, associatedData);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("decrypted failed"));
    }

    ciphertext[0] = original;
    original = associatedData[0];
    associatedData[0] = (byte) ~original;
    try {
      aead.decrypt(ciphertext, associatedData);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("decrypted failed"));
    }
  }

  /**
   * Decodes hex string.
   */
  public static byte[] hexDecode(String hexData) {
    return base16().lowerCase().decode(hexData);
  }
}
