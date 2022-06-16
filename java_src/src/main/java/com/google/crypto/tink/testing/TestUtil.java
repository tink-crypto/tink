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

package com.google.crypto.tink.testing;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.daead.DeterministicAeadConfig;
import com.google.crypto.tink.hybrid.HybridKeyTemplates;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.prf.PrfConfig;
import com.google.crypto.tink.proto.AesCtrHmacAeadKey;
import com.google.crypto.tink.proto.AesCtrHmacStreamingKey;
import com.google.crypto.tink.proto.AesCtrHmacStreamingParams;
import com.google.crypto.tink.proto.AesCtrKey;
import com.google.crypto.tink.proto.AesCtrParams;
import com.google.crypto.tink.proto.AesEaxKey;
import com.google.crypto.tink.proto.AesEaxParams;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingParams;
import com.google.crypto.tink.proto.AesGcmKey;
import com.google.crypto.tink.proto.AesSivKey;
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
import com.google.crypto.tink.proto.HkdfPrfKey;
import com.google.crypto.tink.proto.HkdfPrfParams;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.HmacKeyFormat;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.KeyTypeEntry;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.Keyset.Key;
import com.google.crypto.tink.proto.KeysetInfo;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.proto.RsaSsaPkcs1Params;
import com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.proto.RsaSsaPssParams;
import com.google.crypto.tink.proto.RsaSsaPssPublicKey;
import com.google.crypto.tink.streamingaead.StreamingAeadConfig;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.MessageLite;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;

/** Test helpers. */
public final class TestUtil {
  /** A place holder to keep mutated bytes and its description. */
  public static class BytesMutation {
    public byte[] value;
    public String description;

    public BytesMutation(byte[] value, String description) {
      this.value = value;
      this.description = description;
    }
  }

  // This GCP KMS CryptoKey is restricted to the service account in {@code SERVICE_ACCOUNT_FILE}.
  public static final String RESTRICTED_CRYPTO_KEY_URI =
      String.format(
          "gcp-kms://projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
          "tink-test-infrastructure", "global", "unit-and-integration-testing", "aead-key");

  // This is a credential of a service account that is granted access to
  // {@code RESTRICTED_CRYPTO_KEY_URI}.
  public static final String SERVICE_ACCOUNT_FILE = "testdata/credential.json";

  // This AWS KMS CryptoKey is restricted to Google use only and {@code AWS_CREDS}.
  public static final String AWS_CRYPTO_URI =
      "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f";

  // This is a credential for the AWS service account with granted access to
  // {@code AWS_CRYPTO_URI}.
  public static final String AWS_CREDS = "testdata/credentials_aws.cred";

  /** A dummy Aead-implementation that just throws exception. */
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

  /** @return a {@code PrimitiveSet} from a {@code KeySet} */
  public static <P> PrimitiveSet<P> createPrimitiveSet(Keyset keyset, Class<P> inputClass)
      throws GeneralSecurityException {
    PrimitiveSet.Builder<P> builder = PrimitiveSet.newBuilder(inputClass);
    for (Keyset.Key key : keyset.getKeyList()) {
      if (key.getStatus() == KeyStatusType.ENABLED) {
        P primitive = Registry.getPrimitive(key.getKeyData(), inputClass);
        if (key.getKeyId() == keyset.getPrimaryKeyId()) {
          builder.addPrimaryPrimitive(primitive, key);
        } else {
          builder.addPrimitive(primitive, key);
        }
      }
    }
    return builder.build();
  }

  /** @return a {@code Keyset} from a {@code handle}. */
  public static Keyset getKeyset(final KeysetHandle handle) {
    return CleartextKeysetHandle.getKeyset(handle);
  }

  /** @return a keyset handle from a {@code keyset}. */
  public static KeysetHandle createKeysetHandle(Keyset keyset) throws Exception {
    return CleartextKeysetHandle.parseFrom(keyset.toByteArray());
  }

  /** @return a keyset from a list of keys. The first key is primary. */
  public static Keyset createKeyset(Key primary, Key... keys) throws Exception {
    Keyset.Builder builder = Keyset.newBuilder();
    builder.addKey(primary).setPrimaryKeyId(primary.getKeyId());
    for (Key key : keys) {
      builder.addKey(key);
    }
    return builder.build();
  }

  /** @return a KeyTemplate with an non-existing type url. */
  public static KeyTemplate createKeyTemplateWithNonExistingTypeUrl() throws Exception {
    return KeyTemplate.newBuilder().setTypeUrl("does-not-exist").build();
  }

  /** @return a key with some specified properties. */
  public static Key createKey(
      KeyData keyData, int keyId, KeyStatusType status, OutputPrefixType prefixType)
      throws Exception {
    return Key.newBuilder()
        .setKeyData(keyData)
        .setStatus(status)
        .setKeyId(keyId)
        .setOutputPrefixType(prefixType)
        .build();
  }

  /** @return a {@code HmacKey}. */
  public static HmacKey createHmacKey(byte[] keyValue, int tagSize) throws Exception {
    HmacParams params =
        HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(tagSize).build();

    return HmacKey.newBuilder()
        .setParams(params)
        .setKeyValue(ByteString.copyFrom(keyValue))
        .build();
  }

  /** @return a {@code HkdfPrfKey}. */
  public static HkdfPrfKey createPrfKey(byte[] keyValue) throws Exception {
    HkdfPrfParams params = HkdfPrfParams.newBuilder().setHash(HashType.SHA256).build();

    return HkdfPrfKey.newBuilder()
        .setParams(params)
        .setKeyValue(ByteString.copyFrom(keyValue))
        .build();
  }

  /** @return a {@code KeyData} from a specified key. */
  public static KeyData createKeyData(MessageLite key, String typeUrl, KeyData.KeyMaterialType type)
      throws Exception {
    return KeyData.newBuilder()
        .setValue(key.toByteString())
        .setTypeUrl(typeUrl)
        .setKeyMaterialType(type)
        .build();
  }

  /** @return a {@code KeyData} containing a {@code HmacKey}. */
  public static KeyData createHmacKeyData(byte[] keyValue, int tagSize) throws Exception {
    return createKeyData(
        createHmacKey(keyValue, tagSize),
        MacConfig.HMAC_TYPE_URL,
        KeyData.KeyMaterialType.SYMMETRIC);
  }

  /** @return a {@code KeyData} containing a {@code HkdfPrfKey}. */
  public static KeyData createPrfKeyData(byte[] keyValue) throws Exception {
    return createKeyData(
        createPrfKey(keyValue), PrfConfig.PRF_TYPE_URL, KeyData.KeyMaterialType.SYMMETRIC);
  }

  /** @return a {@code AesCtrKey}. */
  public static AesCtrKey createAesCtrKey(byte[] keyValue, int ivSize) throws Exception {
    AesCtrParams aesCtrParams = AesCtrParams.newBuilder().setIvSize(ivSize).build();
    return AesCtrKey.newBuilder()
        .setParams(aesCtrParams)
        .setKeyValue(ByteString.copyFrom(keyValue))
        .build();
  }

  /** @return a {@code KeyData} containing a {@code AesCtrHmacStreamingKey}. */
  public static KeyData createAesCtrHmacStreamingKeyData(
      byte[] keyValue, int derivedKeySize, int ciphertextSegmentSize) throws Exception {
    HmacParams hmacParams = HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(16).build();
    AesCtrHmacStreamingParams keyParams =
        AesCtrHmacStreamingParams.newBuilder()
            .setCiphertextSegmentSize(ciphertextSegmentSize)
            .setDerivedKeySize(derivedKeySize)
            .setHkdfHashType(HashType.SHA256)
            .setHmacParams(hmacParams)
            .build();
    AesCtrHmacStreamingKey keyProto =
        AesCtrHmacStreamingKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(keyValue))
            .setParams(keyParams)
            .build();
    return createKeyData(
        keyProto,
        StreamingAeadConfig.AES_CTR_HMAC_STREAMINGAEAD_TYPE_URL,
        KeyData.KeyMaterialType.SYMMETRIC);
  }

  /** @return a {@code KeyData} containing a {@code AesGcmHkdfStreamingKey}. */
  public static KeyData createAesGcmHkdfStreamingKeyData(
      byte[] keyValue, int derivedKeySize, int ciphertextSegmentSize) throws Exception {
    AesGcmHkdfStreamingParams keyParams =
        AesGcmHkdfStreamingParams.newBuilder()
            .setCiphertextSegmentSize(ciphertextSegmentSize)
            .setDerivedKeySize(derivedKeySize)
            .setHkdfHashType(HashType.SHA256)
            .build();
    AesGcmHkdfStreamingKey keyProto =
        AesGcmHkdfStreamingKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(keyValue))
            .setParams(keyParams)
            .build();
    return createKeyData(
        keyProto,
        StreamingAeadConfig.AES_GCM_HKDF_STREAMINGAEAD_TYPE_URL,
        KeyData.KeyMaterialType.SYMMETRIC);
  }

  /** @return a {@code KeyData} containing a {@code AesCtrHmacAeadKey}. */
  public static KeyData createAesCtrHmacAeadKeyData(
      byte[] aesCtrKeyValue, int ivSize, byte[] hmacKeyValue, int tagSize) throws Exception {
    AesCtrKey aesCtrKey = createAesCtrKey(aesCtrKeyValue, ivSize);
    HmacKey hmacKey = createHmacKey(hmacKeyValue, tagSize);

    AesCtrHmacAeadKey keyProto =
        AesCtrHmacAeadKey.newBuilder().setAesCtrKey(aesCtrKey).setHmacKey(hmacKey).build();
    return createKeyData(
        keyProto, AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL, KeyData.KeyMaterialType.SYMMETRIC);
  }

  /** @return a {@code KeyData} containing a {@code AesSivKey}. */
  public static KeyData createAesSivKeyData(int keySize) throws Exception {
    AesSivKey keyProto =
        AesSivKey.newBuilder().setKeyValue(ByteString.copyFrom(Random.randBytes(keySize))).build();
    return TestUtil.createKeyData(
        keyProto, DeterministicAeadConfig.AES_SIV_TYPE_URL, KeyData.KeyMaterialType.SYMMETRIC);
  }

  /** @return a {@code KeyData} containing a {@code AesGcmKey}. */
  public static KeyData createAesGcmKeyData(byte[] keyValue) throws Exception {
    AesGcmKey keyProto = AesGcmKey.newBuilder().setKeyValue(ByteString.copyFrom(keyValue)).build();
    return createKeyData(keyProto, AeadConfig.AES_GCM_TYPE_URL, KeyData.KeyMaterialType.SYMMETRIC);
  }

  /** @return a {@code KeyData} containing a {@code AesEaxKey}. */
  public static KeyData createAesEaxKeyData(byte[] keyValue, int ivSizeInBytes) throws Exception {
    AesEaxKey keyProto =
        AesEaxKey.newBuilder()
            .setKeyValue(ByteString.copyFrom(keyValue))
            .setParams(AesEaxParams.newBuilder().setIvSize(ivSizeInBytes).build())
            .build();
    return createKeyData(keyProto, AeadConfig.AES_EAX_TYPE_URL, KeyData.KeyMaterialType.SYMMETRIC);
  }

  /** @return a KMS key URI in a format defined by Google Cloud KMS. */
  public static String createGcpKmsKeyUri(
      String projectId, String location, String ringId, String keyId) {
    return String.format(
        "projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s", projectId, location, ringId, keyId);
  }

  /**
   * @return a {@code EcdsaPrivateKey} constructed from {@code EcdsaPublicKey} and the byte array of
   *     private key.
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
   * @return a {@code EcdsaPublicKey} constructed from {@code EllipticCurveType} and {@code
   *     HashType}.
   */
  public static EcdsaPublicKey generateEcdsaPubKey(
      EllipticCurveType curve, HashType hashType, EcdsaSignatureEncoding encoding)
      throws Exception {
    EcdsaPrivateKey privKey = generateEcdsaPrivKey(curve, hashType, encoding);
    return privKey.getPublicKey();
  }

  /**
   * @return a {@code EcdsaPrivateKey} constructed from {@code EllipticCurveType} and {@code
   *     HashType}.
   */
  public static EcdsaPrivateKey generateEcdsaPrivKey(
      EllipticCurveType curve, HashType hashType, EcdsaSignatureEncoding encoding)
      throws Exception {
    ECParameterSpec ecParams;
    switch (curve) {
      case NIST_P256:
        ecParams = EllipticCurves.getNistP256Params();
        break;
      case NIST_P384:
        ecParams = EllipticCurves.getNistP384Params();
        break;
      case NIST_P521:
        ecParams = EllipticCurves.getNistP521Params();
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
    EcdsaPublicKey ecdsaPubKey =
        createEcdsaPubKey(
            hashType, curve, encoding, w.getAffineX().toByteArray(), w.getAffineY().toByteArray());

    return createEcdsaPrivKey(ecdsaPubKey, privKey.getS().toByteArray());
  }

  /**
   * @return a {@code EcdsaPublicKey} constructed from {@code HashType}, {@code EllipticCurveType}
   *     and affine coordinates of the public key.
   */
  public static EcdsaPublicKey createEcdsaPubKey(
      HashType hashType,
      EllipticCurveType curve,
      EcdsaSignatureEncoding encoding,
      byte[] pubX,
      byte[] pubY)
      throws Exception {
    final int version = 0;
    EcdsaParams ecdsaParams =
        EcdsaParams.newBuilder()
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
   * @return a {@code RsaSsaPkcs1PublicKey} constructed from {@code modulus}, {@code exponent} and
   *     {@code hashType}.
   */
  public static RsaSsaPkcs1PublicKey createRsaSsaPkcs1PubKey(
      byte[] modulus, byte[] exponent, HashType hashType) throws Exception {
    final int version = 0;
    RsaSsaPkcs1Params params = RsaSsaPkcs1Params.newBuilder().setHashType(hashType).build();

    return RsaSsaPkcs1PublicKey.newBuilder()
        .setVersion(version)
        .setParams(params)
        .setN(ByteString.copyFrom(modulus))
        .setE(ByteString.copyFrom(exponent))
        .build();
  }

  /**
   * Returns a {@code RsaSsaPssPublicKey} constructed from {@code modulus}, {@code exponent}, {@code
   * sigHash}, {@code mgf1Hash} and {@code saltLength}.
   */
  public static RsaSsaPssPublicKey createRsaSsaPssPubKey(
      byte[] modulus, byte[] exponent, HashType sigHash, HashType mgf1Hash, int saltLength)
      throws Exception {
    final int version = 0;
    RsaSsaPssParams params =
        RsaSsaPssParams.newBuilder()
            .setSigHash(sigHash)
            .setMgf1Hash(mgf1Hash)
            .setSaltLength(saltLength)
            .build();

    return RsaSsaPssPublicKey.newBuilder()
        .setVersion(version)
        .setParams(params)
        .setN(ByteString.copyFrom(modulus))
        .setE(ByteString.copyFrom(exponent))
        .build();
  }
  /**
   * @return a freshly generated {@code EciesAeadHkdfPrivateKey} constructed with specified
   *     parameters.
   */
  public static EciesAeadHkdfPrivateKey generateEciesAeadHkdfPrivKey(
      EllipticCurveType curve,
      HashType hashType,
      EcPointFormat pointFormat,
      KeyTemplate demKeyTemplate,
      byte[] salt)
      throws Exception {
    ECParameterSpec ecParams;
    switch (curve) {
      case NIST_P256:
        ecParams = EllipticCurves.getNistP256Params();
        break;
      case NIST_P384:
        ecParams = EllipticCurves.getNistP384Params();
        break;
      case NIST_P521:
        ecParams = EllipticCurves.getNistP521Params();
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
    EciesAeadHkdfPublicKey eciesPubKey =
        createEciesAeadHkdfPubKey(
            curve,
            hashType,
            pointFormat,
            demKeyTemplate,
            w.getAffineX().toByteArray(),
            w.getAffineY().toByteArray(),
            salt);
    return createEciesAeadHkdfPrivKey(eciesPubKey, privKey.getS().toByteArray());
  }

  /**
   * @return a {@code KeyData} containing a {@code EciesAeadHkdfPrivateKey} with the specified key
   *     material and parameters.
   */
  public static EciesAeadHkdfPrivateKey createEciesAeadHkdfPrivKey(
      EciesAeadHkdfPublicKey pubKey, byte[] privKeyValue) throws Exception {
    final int version = 0;
    return EciesAeadHkdfPrivateKey.newBuilder()
        .setVersion(version)
        .setPublicKey(pubKey)
        .setKeyValue(ByteString.copyFrom(privKeyValue))
        .build();
  }

  /** @return a {@code EciesAeadHkdfPublicKey} with the specified key material and parameters. */
  public static EciesAeadHkdfPublicKey createEciesAeadHkdfPubKey(
      EllipticCurveType curve,
      HashType hashType,
      EcPointFormat ecPointFormat,
      KeyTemplate demKeyTemplate,
      byte[] pubX,
      byte[] pubY,
      byte[] salt)
      throws Exception {
    final int version = 0;
    EciesAeadHkdfParams params =
        HybridKeyTemplates.createEciesAeadHkdfParams(
            curve, hashType, ecPointFormat, demKeyTemplate, salt);
    return EciesAeadHkdfPublicKey.newBuilder()
        .setVersion(version)
        .setParams(params)
        .setX(ByteString.copyFrom(pubX))
        .setY(ByteString.copyFrom(pubY))
        .build();
  }

  /** Runs basic tests against an Aead primitive. */
  public static void runBasicAeadTests(Aead aead) throws Exception {
    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    byte[] decrypted = aead.decrypt(ciphertext, associatedData);
    assertArrayEquals(plaintext, decrypted);
  }

  /** Decodes hex string. */
  public static byte[] hexDecode(String hexData) {
    return Hex.decode(hexData);
  }

  /** Encodes bytes to hex string. */
  public static String hexEncode(byte[] data) {
    return Hex.encode(data);
  }

  /** @return true iff two arrays are equal. */
  public static boolean arrayEquals(byte[] a, byte[] b) {
    if (a.length != b.length) {
      return false;
    }
    byte res = 0;
    for (int i = 0; i < a.length; i++) {
      res |= (byte) (a[i] ^ b[i]);
    }
    return res == 0;
  }

  /**
   * Best-effort checks that this is Android.
   *
   * @return true if running on Android.
   */
  public static boolean isAndroid() {
    // https://developer.android.com/reference/java/lang/System#getProperties%28%29
    return "The Android Project".equals(System.getProperty("java.vendor"));
  }

  /**
   * Check that this is running in Remote Build Execution.
   *
   * @return true if running on Remote Build Execution.
   */
  public static boolean isRemoteBuildExecution() {
    // This check depends on the system property rbe being set to 1.
    // The property is set in kokoro/presubmit-remote.sh via bazel: --jvmopt=-Drbe=1.
    return "1".equals(System.getProperty("rbe"));
  }

  /**
   * Best-effort checks that this is running under tsan. Returns false in doubt and externally to
   * google.
   */
  public static boolean isTsan() {
    return false;
  }

  /** Returns whether we should skip a test with some AES key size. */
  public static boolean shouldSkipTestWithAesKeySize(int keySizeInBytes)
      throws NoSuchAlgorithmException {
    int maxKeySize = Cipher.getMaxAllowedKeyLength("AES/CTR/NoPadding");
    if ((keySizeInBytes * 8) > maxKeySize) {
      System.out.println(
          String.format(
              "Unlimited Strength Jurisdiction Policy Files are required"
                  + " but not installed. Skip tests with keys larger than %s bits.",
              maxKeySize));
      return true;
    }
    // Android is using Conscrypt as its default JCE provider, but Conscrypt
    // does not support 192-bit keys.
    if (isAndroid() && keySizeInBytes == 24) {
      System.out.println("Skipping tests with 192-bit keys on Android");
      return true;
    }

    return false;
  }

  /**
   * Assertion that an exception's message contains the right message. When this fails, the
   * exception's message and the expected value will be in the failure log.
   */
  public static void assertExceptionContains(Throwable e, String contains) {
    String message =
        String.format(
            "Got exception with message \"%s\", expected it to contain \"%s\".",
            e.getMessage(), contains);
    assertTrue(message, e.getMessage().contains(contains));
  }

  /** Asserts that {@code key} is generated from {@code keyTemplate}. */
  public static void assertHmacKey(com.google.crypto.tink.KeyTemplate keyTemplate, Keyset.Key key)
      throws Exception {
    assertThat(key.getKeyId()).isGreaterThan(0);
    assertThat(key.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(key.getOutputPrefixType()).isEqualTo(OutputPrefixType.TINK);
    assertThat(key.hasKeyData()).isTrue();
    assertThat(key.getKeyData().getTypeUrl()).isEqualTo(keyTemplate.getTypeUrl());

    HmacKeyFormat hmacKeyFormat =
        HmacKeyFormat.parseFrom(keyTemplate.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    HmacKey hmacKey =
        HmacKey.parseFrom(key.getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(hmacKey.getParams()).isEqualTo(hmacKeyFormat.getParams());
    assertThat(hmacKey.getKeyValue().size()).isEqualTo(hmacKeyFormat.getKeySize());
  }

  /** Asserts that {@code KeyInfo} is corresponding to a key from {@code keyTemplate}. */
  public static void assertKeyInfo(
      com.google.crypto.tink.KeyTemplate keyTemplate, KeysetInfo.KeyInfo keyInfo) throws Exception {
    assertThat(keyInfo.getKeyId()).isGreaterThan(0);
    assertThat(keyInfo.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(keyInfo.getOutputPrefixType()).isEqualTo(OutputPrefixType.TINK);
    assertThat(keyInfo.getTypeUrl()).isEqualTo(keyTemplate.getTypeUrl());
  }

  /**
   * Replacement for org.junit.Assert.assertEquals, since org.junit.Assert.assertEquals is quite
   * slow.
   */
  public static void assertByteArrayEquals(String txt, byte[] expected, byte[] actual)
      throws Exception {
    assertEquals(txt + " arrays not of the same length", expected.length, actual.length);
    for (int i = 0; i < expected.length; i++) {
      if (expected[i] != actual[i]) {
        assertEquals(txt + " difference at position:" + i, expected[i], actual[i]);
      }
    }
  }

  public static void assertByteArrayEquals(byte[] expected, byte[] actual) throws Exception {
    assertByteArrayEquals("", expected, actual);
  }

  /**
   * Checks whether the bytes from buffer.position() to buffer.limit() are the same bytes as
   * expected.
   */
  public static void assertByteBufferContains(String txt, byte[] expected, ByteBuffer buffer)
      throws Exception {
    assertEquals(
        txt + " unexpected number of bytes in buffer", expected.length, buffer.remaining());
    byte[] content = new byte[buffer.remaining()];
    buffer.duplicate().get(content);
    assertByteArrayEquals(txt, expected, content);
  }

  public static void assertByteBufferContains(byte[] expected, ByteBuffer buffer) throws Exception {
    assertByteBufferContains("", expected, buffer);
  }

  /** Verifies that the given entry has the specified contents. */
  public static void verifyConfigEntry(
      KeyTypeEntry entry,
      String catalogueName,
      String primitiveName,
      String typeUrl,
      Boolean newKeyAllowed,
      int keyManagerVersion) {
    assertEquals(catalogueName, entry.getCatalogueName());
    assertEquals(primitiveName, entry.getPrimitiveName());
    assertEquals(typeUrl, entry.getTypeUrl());
    assertEquals(newKeyAllowed, entry.getNewKeyAllowed());
    assertEquals(keyManagerVersion, entry.getKeyManagerVersion());
  }

  /** Convert an array of long to an array of int. */
  public static int[] twoCompInt(long[] a) {
    int[] ret = new int[a.length];
    for (int i = 0; i < a.length; i++) {
      ret[i] = (int) (a[i] - (a[i] > Integer.MAX_VALUE ? (1L << 32) : 0));
    }
    return ret;
  }

  /**
   * Generates mutations of {@code bytes}, e.g., flipping bits and truncating.
   *
   * @return a list of pairs of mutated value and mutation description.
   */
  public static List<BytesMutation> generateMutations(byte[] bytes) {
    List<BytesMutation> res = new ArrayList<BytesMutation>();

    // Flip bits.
    for (int i = 0; i < bytes.length; i++) {
      for (int j = 0; j < 8; j++) {
        byte[] modifiedBytes = Arrays.copyOf(bytes, bytes.length);
        modifiedBytes[i] = (byte) (modifiedBytes[i] ^ (1 << j));
        res.add(new BytesMutation(modifiedBytes, String.format("Flip bit %d of data", i)));
      }
    }

    // Truncate bytes.
    for (int i = 0; i < bytes.length; i++) {
      byte[] modifiedBytes = Arrays.copyOf(bytes, i);
      res.add(new BytesMutation(modifiedBytes, String.format("Truncate upto %d bytes of data", i)));
    }

    // Append an extra byte.
    res.add(new BytesMutation(Arrays.copyOf(bytes, bytes.length + 1), "Append an extra zero byte"));
    return res;
  }


  /**
   * Uses a z test on the given byte string, expecting all bits to be uniformly set with probability
   * 1/2. Returns non ok status if the z test fails by more than 10 standard deviations.
   *
   * <p>With less statistics jargon: This counts the number of bits set and expects the number to be
   * roughly half of the length of the string. The law of large numbers suggests that we can assume
   * that the longer the string is, the more accurate that estimate becomes for a random string.
   * This test is useful to detect things like strings that are entirely zero.
   *
   * <p>Note: By itself, this is a very weak test for randomness.
   *
   * @throws GeneralSecurityException if uniformity error is detected, otherwise returns normally.
   */
  public static void ztestUniformString(byte[] string) throws GeneralSecurityException {
    final double minAcceptableStdDevs = 10.0;
    double totalBits = string.length * 8;
    double expected = totalBits / 2.0;
    double stddev = Math.sqrt(totalBits / 4.0);

    // This test is very limited at low string lengths. Below a certain threshold it tests nothing.
    if (expected < stddev * minAcceptableStdDevs) {
      throw new GeneralSecurityException(
          "Test will always succeed with strings of the given length "
              + string.length
              + ". Use more bytes.");
    }

    long numSetBits = 0;
    for (byte b : string) {
      int unsignedInt = toUnsignedInt(b);
      // Counting the number of bits set in byte:
      while (unsignedInt != 0) {
        numSetBits++;
        unsignedInt = (unsignedInt & (unsignedInt - 1));
      }
    }
    // Check that the number of bits is within 10 stddevs.
    if (Math.abs((double) numSetBits - expected) < minAcceptableStdDevs * stddev) {
      return;
    }
    throw new GeneralSecurityException(
        "Z test for uniformly distributed variable out of bounds; "
            + "Actual number of set bits was "
            + numSetBits
            + " expected was "
            + expected
            + " 10 * standard deviation is 10 * "
            + stddev
            + " = "
            + 10.0 * stddev);
  }

  /**
   * Tests that the crosscorrelation of two strings of equal length points to independent and
   * uniformly distributed strings. Returns non ok status if the z test fails by more than 10
   * standard deviations.
   *
   * <p>With less statistics jargon: This xors two strings and then performs the ZTestUniformString
   * on the result. If the two strings are independent and uniformly distributed, the xor'ed string
   * is as well. A cross correlation test will find whether two strings overlap more or less than it
   * would be expected.
   *
   * <p>Note: Having a correlation of zero is only a necessary but not sufficient condition for
   * independence.
   *
   * @throws GeneralSecurityException if uniformity error is detected, otherwise returns normally.
   */
  public static void ztestCrossCorrelationUniformStrings(byte[] string1, byte[] string2)
      throws GeneralSecurityException {
    if (string1.length != string2.length) {
      throw new GeneralSecurityException("Strings are not of equal length");
    }
    byte[] crossed = new byte[string1.length];
    for (int i = 0; i < string1.length; i++) {
      crossed[i] = (byte) (string1[i] ^ string2[i]);
    }
    ztestUniformString(crossed);
  }

  /**
   * Tests that the autocorrelation of a string points to the bits being independent and uniformly
   * distributed. Rotates the string in a cyclic fashion. Returns non ok status if the z test fails
   * by more than 10 standard deviations.
   *
   * <p>With less statistics jargon: This rotates the string bit by bit and performs
   * ZTestCrosscorrelationUniformStrings on each of the rotated strings and the original. This will
   * find self similarity of the input string, especially periodic self similarity. For example, it
   * is a decent test to find English text (needs about 180 characters with the current settings).
   *
   * <p>Note: Having a correlation of zero is only a necessary but not sufficient condition for
   * independence.
   *
   * @throws GeneralSecurityException if uniformity error is detected, otherwise returns normally.
   */
  public static void ztestAutocorrelationUniformString(byte[] string)
      throws GeneralSecurityException {
    byte[] rotated = Arrays.copyOf(string, string.length);

    for (int i = 1; i < string.length * 8; i++) {
      rotate(rotated);
      ztestCrossCorrelationUniformStrings(string, rotated);
    }
  }

  /** Manual implementation of Byte.toUnsignedByte. The Android JDK does not have this method. */
  private static int toUnsignedInt(byte b) {
    return b & 0xff;
  }

  private static void rotate(byte[] string) {
    byte[] ref = Arrays.copyOf(string, string.length);
    for (int i = 0; i < string.length; i++) {
      string[i] =
          (byte)
              ((toUnsignedInt(string[i]) >> 1)
                  | ((1 & toUnsignedInt(ref[(i == 0 ? string.length : i) - 1])) << 7));
    }
  }

  private TestUtil() {}
}
