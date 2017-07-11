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
// See the License for the specified language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink;

import static com.google.common.io.BaseEncoding.base16;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import com.google.common.base.Optional;
import com.google.crypto.tink.aead.AeadFactory;
import com.google.crypto.tink.aead.AesEaxKeyManager;
import com.google.crypto.tink.aead.AesGcmKeyManager;
import com.google.crypto.tink.hybrid.HybridKeyTemplates;
import com.google.crypto.tink.mac.HmacKeyManager;
import com.google.crypto.tink.proto.AesCtrHmacAeadKey;
import com.google.crypto.tink.proto.AesCtrKey;
import com.google.crypto.tink.proto.AesCtrParams;
import com.google.crypto.tink.proto.AesEaxKey;
import com.google.crypto.tink.proto.AesEaxParams;
import com.google.crypto.tink.proto.AesGcmKey;
import com.google.crypto.tink.proto.EcPointFormat;
import com.google.crypto.tink.proto.EcdsaParams;
import com.google.crypto.tink.proto.EcdsaPrivateKey;
import com.google.crypto.tink.proto.EcdsaPublicKey;
import com.google.crypto.tink.proto.EcdsaSignatureEncoding;
import com.google.crypto.tink.proto.EciesAeadHkdfParams;
import com.google.crypto.tink.proto.EciesAeadHkdfPrivateKey;
import com.google.crypto.tink.proto.EciesAeadHkdfPublicKey;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.Keyset.Key;
import com.google.crypto.tink.proto.KmsEnvelopeAeadKey;
import com.google.crypto.tink.proto.KmsEnvelopeAeadKeyFormat;
import com.google.crypto.tink.proto.KmsEnvelopeAeadParams;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.EcUtil;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import com.google.protobuf.MessageLite;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

/**
 * Test helpers.
 */
public class TestUtil {
  // This GCP KMS CryptoKey is restricted to the service account in {@code SERVICE_ACCOUNT_FILE}.
  public static final String RESTRICTED_CRYPTO_KEY_URI = String.format(
        "projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
        "tink-test-infrastructure", "global", "unit-and-integration-testing", "aead-key");

  // This is a credential of a service account that is granted access to
  // {@code RESTRICTED_CRYPTO_KEY_URI}.
  public static final Optional<File> SERVICE_ACCOUNT_FILE = Optional.of(Paths.get(
      "testdata/credential.json")
      .toFile());

  /**
   * A dummy Aead-implementation that just throws exception.
   */
  public static class DummyAead implements Aead {
    public DummyAead() {}
    @Override
    public byte[] encrypt(byte[] plaintext, byte[] aad) throws GeneralSecurityException {
      throw new GeneralSecurityException("dummy");
    }
    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] aad) throws GeneralSecurityException {
      throw new GeneralSecurityException("dummy");
    }
  }

  /**
   * Implements a SeekableByteChannel for testing.
   * The implementation is backed by a ByteBuffer.
   */
  public static class ByteBufferChannel implements SeekableByteChannel {
    private final ByteBuffer buffer;

    /**
     * Defines the maximal size of a chunk that is transferred with a single write.
     * This can be used to test the behavior of streaming encryption with channels
     * where not always sufficiently many bytes are available during reads and writes.
     */
    private final int maxChunkSize;

    /**
     * keeps track whether the channel is still open.
     */
    private boolean isopen;

    public ByteBufferChannel(ByteBuffer buffer) {
      this.buffer = buffer.duplicate();
      maxChunkSize = java.lang.Integer.MAX_VALUE;
      isopen = true;
    }

    public ByteBufferChannel(ByteBuffer buffer, int maxChunkSize) {
      this.buffer = buffer.duplicate();
      this.maxChunkSize = maxChunkSize;
      isopen = true;
    }

    public ByteBufferChannel(byte[] bytes) {
      this.buffer = ByteBuffer.wrap(bytes);
      maxChunkSize = java.lang.Integer.MAX_VALUE;
      isopen = true;
    }

    private void checkIsOpen() throws ClosedChannelException {
      if (!isopen) {
        throw new ClosedChannelException();
      }
    }

    @Override
    public long position() throws ClosedChannelException {
      checkIsOpen();
      return buffer.position();
    }

    @Override
    public synchronized ByteBufferChannel position(long newPosition)
        throws ClosedChannelException {
      checkIsOpen();
      if (newPosition < 0) {
        throw new IllegalArgumentException("negative position");
      }
      if (newPosition > buffer.limit()) {
        newPosition = buffer.limit();
      }
      buffer.position((int) newPosition);
      return this;
    }

    @Override
    public synchronized int read(ByteBuffer dst) throws IOException {
      checkIsOpen();
      if (buffer.remaining() == 0) {
        return -1;
      }
      // Not the most efficient way.
      int size = Math.min(buffer.remaining(), dst.remaining());
      size = Math.min(size, maxChunkSize);
      byte[] bytes = new byte[size];
      buffer.get(bytes);
      dst.put(bytes);
      return size;
    }

    @Override
    public int write(ByteBuffer src) throws IOException {
      checkIsOpen();
      // not the most efficient way
      int size = Math.min(buffer.remaining(), src.remaining());
      size = Math.min(size, maxChunkSize);
      byte[] bytes = new byte[size];
      src.get(bytes);
      buffer.put(bytes);
      return size;
    }

    @Override
    public long size() throws ClosedChannelException {
      checkIsOpen();
      return buffer.limit();
    }

    @Override
    public SeekableByteChannel truncate(long size) throws NonWritableChannelException {
      throw new NonWritableChannelException();
    }

    @Override
    public void close() throws IOException {
      isopen = false;
    }

    @Override
    public boolean isOpen() {
      return isopen;
    }

    public void rewind() {
      isopen = true;
      buffer.rewind();
    }
  }

  /**
   * @return a keyset handle from a {@code keyset}.
   */
  public static KeysetHandle createKeysetHandle(final Keyset keyset) throws Exception {
    return new KeysetHandle(keyset);
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
   * @return a key with some specified properties.
   */
  public static Key createKey(KeyData keyData, int keyId, KeyStatusType status,
      OutputPrefixType prefixType) throws Exception {
    return Key.newBuilder()
        .setKeyData(keyData)
        .setStatus(status)
        .setKeyId(keyId)
        .setOutputPrefixType(prefixType)
        .build();
  }

  /**
   * @return a {@code HmacKey}.
   */
  public static HmacKey createHmacKey(byte[] keyValue, int tagSize) throws Exception {
    HmacParams params = HmacParams.newBuilder()
        .setHash(HashType.SHA256)
        .setTagSize(tagSize)
        .build();

    return HmacKey.newBuilder()
        .setParams(params)
        .setKeyValue(ByteString.copyFrom(keyValue))
        .build();
  }

  /**
   * @return a {@code KeyData} from a specified key.
   */
  public static KeyData createKeyData(MessageLite key, String typeUrl, KeyData.KeyMaterialType type)
      throws Exception {
    return KeyData.newBuilder()
        .setValue(key.toByteString())
        .setTypeUrl(typeUrl)
        .setKeyMaterialType(type)
        .build();
  }

  /**
   * @return a {@code KeyData} containing a {@code HmacKey}.
   */
  public static KeyData createHmacKeyData(byte[] keyValue, int tagSize) throws Exception {
    return createKeyData(
        createHmacKey(keyValue, tagSize),
        HmacKeyManager.TYPE_URL,
        KeyData.KeyMaterialType.SYMMETRIC);
  }

  /**
   * @return a {@code AesCtrKey}.
   */
  public static AesCtrKey createAesCtrKey(byte[] keyValue, int ivSize) throws Exception {
    AesCtrParams aesCtrParams = AesCtrParams.newBuilder()
        .setIvSize(ivSize)
        .build();
    return AesCtrKey.newBuilder()
        .setParams(aesCtrParams)
        .setKeyValue(ByteString.copyFrom(keyValue))
        .build();
  }

  /**
   * @return a {@code KeyData} containing a {@code AesCtrHmacAeadKey}.
   */
  public static KeyData createAesCtrHmacAeadKeyData(byte[] aesCtrKeyValue, int ivSize,
      byte[] hmacKeyValue, int tagSize) throws Exception {
    AesCtrKey aesCtrKey = createAesCtrKey(aesCtrKeyValue, ivSize);
    HmacKey hmacKey = createHmacKey(hmacKeyValue, tagSize);

    AesCtrHmacAeadKey keyProto = AesCtrHmacAeadKey.newBuilder()
        .setAesCtrKey(aesCtrKey)
        .setHmacKey(hmacKey)
        .build();
    return createKeyData(
        keyProto,
        "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
        KeyData.KeyMaterialType.SYMMETRIC);
  }

  /**
   * @return a {@code KeyData} containing a {@code AesGcmKey}.
   */
  public static KeyData createAesGcmKeyData(byte[] keyValue) throws Exception {
    AesGcmKey keyProto = AesGcmKey.newBuilder()
        .setKeyValue(ByteString.copyFrom(keyValue))
        .build();
    return createKeyData(
        keyProto,
        AesGcmKeyManager.TYPE_URL,
        KeyData.KeyMaterialType.SYMMETRIC);
  }

  /**
   * @return a {@code KeyData} containing a {@code AesEaxKey}.
   */
  public static KeyData createAesEaxKeyData(byte[] keyValue, int ivSizeInBytes) throws Exception {
    AesEaxKey keyProto = AesEaxKey.newBuilder()
        .setKeyValue(ByteString.copyFrom(keyValue))
        .setParams(AesEaxParams.newBuilder().setIvSize(ivSizeInBytes).build())
        .build();
    return createKeyData(
        keyProto,
        AesEaxKeyManager.TYPE_URL,
        KeyData.KeyMaterialType.SYMMETRIC);
  }

  /**
   * @return a {@code KeyData} containing a {@code KmsEnvelopeAeadKey}.
   */
  public static KeyData createKmsEnvelopeAeadKeyData(KeyData kmsKey,
      KeyTemplate dekTemplate) throws Exception {
    KmsEnvelopeAeadParams params = KmsEnvelopeAeadParams.newBuilder()
        .setDekTemplate(dekTemplate)
        .setKmsKey(kmsKey)
        .build();
    KmsEnvelopeAeadKey keyProto = KmsEnvelopeAeadKey.newBuilder().setParams(params).build();
    return createKeyData(
        keyProto,
        "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey",
        KeyData.KeyMaterialType.REMOTE);
  }

  /**
   * @return a {@code KeyTemplate} containing {@code KmsEnvelopeAeadKey}.
   */
  public static KeyTemplate createKmsEnvelopeAeadKeyTemplate(KeyData kmsKey,
      KeyTemplate dekTemplate) throws Exception {
    KmsEnvelopeAeadParams params = KmsEnvelopeAeadParams.newBuilder()
        .setDekTemplate(dekTemplate)
        .setKmsKey(kmsKey)
        .build();
    KmsEnvelopeAeadKeyFormat format = KmsEnvelopeAeadKeyFormat.newBuilder()
        .setParams(params)
        .build();
    return KeyTemplate.newBuilder()
        .setValue(format.toByteString())
        .setTypeUrl("type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey")
        .build();
  }

  /**
   * @return a KMS key URI in a format defined by Google Cloud KMS.
   */
  public static String createGcpKmsKeyUri(
    String projectId, String location, String ringId, String keyId) {
    return String.format(
        "projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
        projectId, location, ringId, keyId);
  }

  /**
   * @return a {@code EcdsaPrivateKey} constructed from {@code EcdsaPublicKey} and the byte array
   * of private key.
   */
  public static EcdsaPrivateKey createEcdsaPrivKey(EcdsaPublicKey pubKey, byte[] privKey) {
    final int version = 0;
    return EcdsaPrivateKey.newBuilder()
        .setVersion(version)
        .setPublicKey(pubKey)
        .setKeyValue(ByteString.copyFrom(privKey))
        .build();
  }

  /**
   * @return a {@code EcdsaPublicKey} constructed from {@code EllipticCurveType} and
   * {@code HashType}.
   */
  public static EcdsaPublicKey generateEcdsaPubKey(EllipticCurveType curve, HashType hashType,
      EcdsaSignatureEncoding encoding)
    throws Exception {
    EcdsaPrivateKey privKey = generateEcdsaPrivKey(curve, hashType, encoding);
    return privKey.getPublicKey();
  }

  /**
   * @return a {@code EcdsaPrivateKey} constructed from {@code EllipticCurveType} and
   * {@code HashType}.
   */
  public static EcdsaPrivateKey generateEcdsaPrivKey(EllipticCurveType curve, HashType hashType,
      EcdsaSignatureEncoding encoding)
      throws Exception {
        ECParameterSpec ecParams;
        switch(curve) {
          case NIST_P256:
            ecParams = EcUtil.getNistP256Params();
            break;
          case NIST_P384:
            ecParams = EcUtil.getNistP384Params();
            break;
          case NIST_P521:
            ecParams = EcUtil.getNistP521Params();
            break;
          default:
            throw new NoSuchAlgorithmException("Curve not implemented:" + curve);
        }
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(ecParams);
        KeyPair keyPair = keyGen.generateKeyPair();
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();
        ECPoint w = pubKey.getW();
        EcdsaPublicKey ecdsaPubKey = createEcdsaPubKey(hashType, curve, encoding,
            w.getAffineX().toByteArray(), w.getAffineY().toByteArray());

        return createEcdsaPrivKey(ecdsaPubKey, privKey.getS().toByteArray());
      }

  /**
   * @return a {@code EcdsaPublicKey} constructed from {@code HashType}, {@code EllipticCurveType}
   * and affine coordinates of the public key.
   */
  public static EcdsaPublicKey createEcdsaPubKey(HashType hashType, EllipticCurveType curve,
      EcdsaSignatureEncoding encoding, byte[] pubX, byte[] pubY) throws Exception {
    final int version = 0;
    EcdsaParams ecdsaParams = EcdsaParams.newBuilder()
        .setHashType(hashType)
        .setCurve(curve)
        .setEncoding(encoding)
        .build();
    return EcdsaPublicKey.newBuilder()
        .setVersion(version)
        .setParams(ecdsaParams)
        .setX(ByteString.copyFrom(pubX))
        .setY(ByteString.copyFrom(pubY))
        .build();
  }

  /**
   * @return a freshly generated {@code EciesAeadHkdfPrivateKey} constructed with specified
   * parameters.
   */
  public static EciesAeadHkdfPrivateKey generateEciesAeadHkdfPrivKey(EllipticCurveType curve,
      HashType hashType, EcPointFormat pointFormat, KeyTemplate demKeyTemplate, byte[] salt)
      throws Exception {
    ECParameterSpec ecParams;
    switch(curve) {
      case NIST_P256:
        ecParams = EcUtil.getNistP256Params();
        break;
      case NIST_P384:
        ecParams = EcUtil.getNistP384Params();
        break;
      case NIST_P521:
        ecParams = EcUtil.getNistP521Params();
        break;
      default:
        throw new NoSuchAlgorithmException("Curve not implemented:" + curve);
    }
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(ecParams);
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();
    ECPoint w = pubKey.getW();
    EciesAeadHkdfPublicKey eciesPubKey = createEciesAeadHkdfPubKey(curve, hashType, pointFormat,
        demKeyTemplate, w.getAffineX().toByteArray(), w.getAffineY().toByteArray(), salt);
    return createEciesAeadHkdfPrivKey(eciesPubKey, privKey.getS().toByteArray());
  }

  /**
   *  @return a {@code KeyData} containing a {@code EciesAeadHkdfPrivateKey} with the specified key
   *  material and parameters.
   */
  public static EciesAeadHkdfPrivateKey createEciesAeadHkdfPrivKey(EciesAeadHkdfPublicKey pubKey,
      byte[] privKeyValue) throws Exception {
    final int version = 0;
    return EciesAeadHkdfPrivateKey.newBuilder()
        .setVersion(version)
        .setPublicKey(pubKey)
        .setKeyValue(ByteString.copyFrom(privKeyValue))
        .build();
  }

  /**
   *  @return a {@code EciesAeadHkdfPublicKey} with the specified key material and parameters.
   */
  public static EciesAeadHkdfPublicKey createEciesAeadHkdfPubKey(EllipticCurveType curve,
      HashType hashType, EcPointFormat ecPointFormat, KeyTemplate demKeyTemplate,
      byte[] pubX, byte[] pubY, byte[] salt) throws Exception {
    final int version = 0;
    EciesAeadHkdfParams params = HybridKeyTemplates.createEciesAeadHkdfParams(
        curve, hashType, ecPointFormat, demKeyTemplate, salt);
    return EciesAeadHkdfPublicKey.newBuilder()
        .setVersion(version)
        .setParams(params)
        .setX(ByteString.copyFrom(pubX))
        .setY(ByteString.copyFrom(pubY))
        .build();
  }

  /**
   * Runs basic tests against an Aead primitive. The given keysetHandle should
   * be an Aead key type.
   */
  public static void runBasicAeadFactoryTests(KeysetHandle keysetHandle) throws Exception {
    runBasicAeadFactoryTests(keysetHandle, /* keyManager*/ null);
  }
  /**
   * Runs basic tests against an Aead primitive. The given keysetHandle should
   * be an Aead key type.
   */
  public static void runBasicAeadFactoryTests(
      KeysetHandle keysetHandle, KeyManager<Aead> keyManager) throws Exception {
    Aead aead = AeadFactory.getPrimitive(keysetHandle, keyManager);
    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    byte[] decrypted = aead.decrypt(ciphertext, associatedData);
    assertArrayEquals(plaintext, decrypted);
  }

  /**
   * Decodes hex string.
   */
  public static byte[] hexDecode(String hexData) {
    return base16().lowerCase().decode(hexData);
  }

  /**
   * Encodes bytes to hex string.
   */
  public static String hexEncode(byte[] data) {
    return base16().lowerCase().encode(data);
  }

  /**
   * Assertion that an exception's message contains the right message. When this fails, the
   * exception's message and the expected value will be in the failure log.
   */
  public static void assertExceptionContains(Throwable e, String contains) {
    String message = String.format(
        "Got exception with message \"%s\", expected it to contain \"%s\".",
        e.getMessage(),
        contains);
    assertTrue(message, e.getMessage().contains(contains));
  }

  /**
   * Generates and returns a random, temporary file path.
   */
  public static Path generateRandomPath(String prefix) {
    String tmpDir = java.lang.System.getenv("TEST_TMPDIR");
    String tmpFilename = String.format("%s.%s.tmp", prefix, new SecureRandom().nextLong());
    return FileSystems.getDefault().getPath(tmpDir, tmpFilename);
  }
}
