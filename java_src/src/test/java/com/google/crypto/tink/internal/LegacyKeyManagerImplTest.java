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

package com.google.crypto.tink.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.PrivateKeyManager;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.mac.internal.HmacProtoSerialization;
import com.google.crypto.tink.proto.EcdsaKeyFormat;
import com.google.crypto.tink.proto.EcdsaParams;
import com.google.crypto.tink.proto.EcdsaPrivateKey;
import com.google.crypto.tink.proto.EcdsaPublicKey;
import com.google.crypto.tink.proto.EcdsaSignatureEncoding;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.HmacKeyFormat;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.internal.EcdsaProtoSerialization;
import com.google.crypto.tink.subtle.EcdsaSignJce;
import com.google.crypto.tink.subtle.EcdsaVerifyJce;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.PrfMac;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import javax.annotation.Nullable;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class LegacyKeyManagerImplTest {

  private static KeyManager<Mac> keyManager;
  private static PrivateKeyManager<PublicKeySign> privateKeyManager;

  private static com.google.crypto.tink.mac.HmacKey createHmacKey(
      com.google.crypto.tink.mac.HmacParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    return com.google.crypto.tink.mac.HmacKey.builder()
        .setParameters(parameters)
        .setKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()))
        .setIdRequirement(idRequirement)
        .build();
  }

  private static com.google.crypto.tink.signature.EcdsaPrivateKey createEcdsaPrivateKey(
      EcdsaParameters parameters, @Nullable Integer idRequirement) throws GeneralSecurityException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(parameters.getCurveType().toParameterSpec());
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
    ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();

    com.google.crypto.tink.signature.EcdsaPublicKey publicKey =
        com.google.crypto.tink.signature.EcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(ecPublicKey.getW())
            .setIdRequirement(idRequirement)
            .build();
    return com.google.crypto.tink.signature.EcdsaPrivateKey.builder()
        .setPublicKey(publicKey)
        .setPrivateValue(
            SecretBigInteger.fromBigInteger(ecPrivateKey.getS(), InsecureSecretKeyAccess.get()))
        .build();
  }

  @BeforeClass
  public static void register() throws GeneralSecurityException {
    HmacProtoSerialization.register();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(
            PrimitiveConstructor.create(
                PrfMac::create, com.google.crypto.tink.mac.HmacKey.class, Mac.class));
    MutableKeyCreationRegistry.globalInstance()
        .add(
            LegacyKeyManagerImplTest::createHmacKey,
            com.google.crypto.tink.mac.HmacParameters.class);

    keyManager =
        LegacyKeyManagerImpl.create(
            "type.googleapis.com/google.crypto.tink.HmacKey",
            Mac.class,
            KeyMaterialType.SYMMETRIC,
            HmacKey.parser());

    EcdsaProtoSerialization.register();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(
            PrimitiveConstructor.create(
                EcdsaSignJce::create,
                com.google.crypto.tink.signature.EcdsaPrivateKey.class,
                PublicKeySign.class));
    MutableKeyCreationRegistry.globalInstance()
        .add(LegacyKeyManagerImplTest::createEcdsaPrivateKey, EcdsaParameters.class);
    privateKeyManager =
        LegacyKeyManagerImpl.createPrivateKeyManager(
            "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
            PublicKeySign.class,
            EcdsaPrivateKey.parser());
  }

  @Test
  public void getPrimitive_messageLite_works() throws Exception {
    HmacKey key =
        HmacKey.newBuilder()
            .setVersion(0)
            .setParams(HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16))
            .setKeyValue(
                ByteString.copyFrom(
                    Hex.decode("816aa4c3ee066310ac1e6666cf830c375355c3c8ba18cfe1f50a48c988b46272")))
            .build();

    Mac mac = keyManager.getPrimitive(key);
    byte[] message =
        Hex.decode(
            "220248f5e6d7a49335b3f91374f18bb8b0ff5e8b9a5853f3cfb293855d78301d837a0a2eb9e4f056f06c08361"
                + "bd07180ee802651e69726c28910d2baef379606815dcbab01d0dc7acb0ba8e65a2928130da0522f2b2b3d05260"
                + "885cf1c64f14ca3145313c685b0274bf6a1cb38e4f99895c6a8cc72fbe0e52c01766fede78a1a");
    byte[] tag = Hex.decode("17cb2e9e98b748b5ae0f7078ea5519e5");

    mac.verifyMac(tag, message);
  }

  @Test
  public void getPrimitive_byteString_works() throws Exception {
    HmacKey key =
        HmacKey.newBuilder()
            .setVersion(0)
            .setParams(HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16))
            .setKeyValue(
                ByteString.copyFrom(
                    Hex.decode("816aa4c3ee066310ac1e6666cf830c375355c3c8ba18cfe1f50a48c988b46272")))
            .build();

    Mac mac = keyManager.getPrimitive(key.toByteString());
    byte[] message =
        Hex.decode(
            "220248f5e6d7a49335b3f91374f18bb8b0ff5e8b9a5853f3cfb293855d78301d837a0a2eb9e4f056f06c08361"
                + "bd07180ee802651e69726c28910d2baef379606815dcbab01d0dc7acb0ba8e65a2928130da0522f2b2b3d05260"
                + "885cf1c64f14ca3145313c685b0274bf6a1cb38e4f99895c6a8cc72fbe0e52c01766fede78a1a");
    byte[] tag = Hex.decode("17cb2e9e98b748b5ae0f7078ea5519e5");

    mac.verifyMac(tag, message);
  }

  @Test
  public void getPrimitive_invalidKey_throws() throws Exception {
    HmacKey key =
        HmacKey.newBuilder()
            .setVersion(0)
            .setParams(HmacParams.newBuilder().setHash(HashType.UNKNOWN_HASH).setTagSize(16))
            .build();

    assertThrows(GeneralSecurityException.class, () -> keyManager.getPrimitive(key));
  }

  @Test
  public void newKey_byteString_works() throws Exception {
    HmacKeyFormat keyFormat =
        HmacKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16))
            .build();

    HmacKey key1 = (HmacKey) keyManager.newKey(keyFormat.toByteString());
    HmacKey key2 = (HmacKey) keyManager.newKey(keyFormat.toByteString());
    assertThat(key1.getKeyValue().size()).isEqualTo(32);
    assertThat(key1.getKeyValue()).isNotEqualTo(key2.getKeyValue());
    assertThat(key1.getParams()).isEqualTo(keyFormat.getParams());
  }

  @Test
  public void newKey_messageLite_works() throws Exception {
    HmacKeyFormat keyFormat =
        HmacKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16))
            .build();

    HmacKey key1 = (HmacKey) keyManager.newKey(keyFormat);
    HmacKey key2 = (HmacKey) keyManager.newKey(keyFormat);
    assertThat(key1.getKeyValue().size()).isEqualTo(32);
    assertThat(key1.getKeyValue()).isNotEqualTo(key2.getKeyValue());
    assertThat(key1.getParams()).isEqualTo(keyFormat.getParams());
  }

  @Test
  public void newKeyData_works() throws Exception {
    HmacKeyFormat keyFormat =
        HmacKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16))
            .build();

    KeyData keyData1 = keyManager.newKeyData(keyFormat.toByteString());
    KeyData keyData2 = keyManager.newKeyData(keyFormat.toByteString());
    assertThat(keyData1.getKeyMaterialType()).isEqualTo(KeyMaterialType.SYMMETRIC);
    assertThat(keyData1.getTypeUrl()).isEqualTo("type.googleapis.com/google.crypto.tink.HmacKey");
    HmacKey key1 = HmacKey.parseFrom(keyData1.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    HmacKey key2 = HmacKey.parseFrom(keyData2.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(key1.getParams()).isEqualTo(keyFormat.getParams());
    assertThat(key1.getKeyValue().size()).isEqualTo(32);
    assertThat(key1.getKeyValue()).isNotEqualTo(key2.getKeyValue());
  }

  @Test
  public void doesSupport_works() throws Exception {
    assertTrue(keyManager.doesSupport("type.googleapis.com/google.crypto.tink.HmacKey"));
    assertFalse(keyManager.doesSupport("type.googleapis.com/google.crypto.tink.SomeOtherKey"));
  }

  @Test
  public void getKeyType_works() throws Exception {
    assertThat(keyManager.getKeyType()).isEqualTo("type.googleapis.com/google.crypto.tink.HmacKey");
  }

  @Test
  public void getVersion_works() throws Exception {
    assertThat(keyManager.getVersion()).isEqualTo(0);
  }

  private static String getHexX() {
    return "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
  }

  private static String getHexY() {
    return "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
  }

  private static String getHexPrivateValue() {
    return "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
  }

  private static com.google.crypto.tink.proto.EcdsaPrivateKey getProtoPrivateKey() {
    com.google.crypto.tink.proto.EcdsaPublicKey protoPublicKey =
        com.google.crypto.tink.proto.EcdsaPublicKey.newBuilder()
            .setVersion(0)
            .setX(ByteString.copyFrom(Hex.decode("00" + getHexX())))
            .setY(ByteString.copyFrom(Hex.decode("00" + getHexY())))
            .setParams(
                EcdsaParams.newBuilder()
                    .setHashType(HashType.SHA256)
                    .setCurve(EllipticCurveType.NIST_P256)
                    .setEncoding(EcdsaSignatureEncoding.IEEE_P1363))
            .build();
    return com.google.crypto.tink.proto.EcdsaPrivateKey.newBuilder()
        .setVersion(0)
        .setPublicKey(protoPublicKey)
        // privateValue is currently serialized with an extra zero at the beginning.
        .setKeyValue(ByteString.copyFrom(Hex.decode("00" + getHexPrivateValue())))
        .build();
  }

  private static com.google.crypto.tink.signature.EcdsaPrivateKey getPlainJavaPrivateKey()
      throws GeneralSecurityException {
    com.google.crypto.tink.signature.EcdsaPublicKey publicKey =
        com.google.crypto.tink.signature.EcdsaPublicKey.builder()
            .setParameters(
                EcdsaParameters.builder()
                    .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                    .setCurveType(EcdsaParameters.CurveType.NIST_P256)
                    .setHashType(EcdsaParameters.HashType.SHA256)
                    .setVariant(EcdsaParameters.Variant.NO_PREFIX)
                    .build())
            .setPublicPoint(
                new ECPoint(new BigInteger(getHexX(), 16), new BigInteger(getHexY(), 16)))
            .build();
    return com.google.crypto.tink.signature.EcdsaPrivateKey.builder()
        .setPublicKey(publicKey)
        .setPrivateValue(
            SecretBigInteger.fromBigInteger(
                new BigInteger(getHexPrivateValue(), 16), InsecureSecretKeyAccess.get()))
        .build();
  }

  @Test
  public void getPrimitiveClass_works() throws Exception {
    assertThat(keyManager.getPrimitiveClass()).isEqualTo(Mac.class);
  }

  @Test
  public void privateKeyManager_getPrimitive_messageLite_works() throws Exception {
    PublicKeySign signer = privateKeyManager.getPrimitive(getProtoPrivateKey());
    PublicKeyVerify verifier = EcdsaVerifyJce.create(getPlainJavaPrivateKey().getPublicKey());
    byte[] message = new byte[] {};
    verifier.verify(signer.sign(message), message);
  }

  @Test
  public void privateKeyManager_getPrimitive_byteString_works() throws Exception {
    PublicKeySign signer = privateKeyManager.getPrimitive(getProtoPrivateKey().toByteString());
    PublicKeyVerify verifier = EcdsaVerifyJce.create(getPlainJavaPrivateKey().getPublicKey());
    byte[] message = new byte[] {};
    verifier.verify(signer.sign(message), message);
  }

  @Test
  public void privateKeyManager_getPrimitive_invalidKey_throws() throws Exception {
    EcdsaPrivateKey key = EcdsaPrivateKey.getDefaultInstance();

    assertThrows(GeneralSecurityException.class, () -> keyManager.getPrimitive(key));
  }

  @Test
  public void privateKeyManager_newKey_byteString_works() throws Exception {
    EcdsaKeyFormat keyFormat =
        EcdsaKeyFormat.newBuilder()
            .setParams(
                EcdsaParams.newBuilder()
                    .setHashType(HashType.SHA256)
                    .setCurve(EllipticCurveType.NIST_P256)
                    .setEncoding(EcdsaSignatureEncoding.IEEE_P1363))
            .build();

    EcdsaPrivateKey key1 = (EcdsaPrivateKey) privateKeyManager.newKey(keyFormat.toByteString());
    EcdsaPrivateKey key2 = (EcdsaPrivateKey) privateKeyManager.newKey(keyFormat.toByteString());
    assertThat(key1.getKeyValue().size()).isEqualTo(33);
    assertThat(key1.getKeyValue()).isNotEqualTo(key2.getKeyValue());
    assertThat(key1.getPublicKey().getParams()).isEqualTo(keyFormat.getParams());
  }

  @Test
  public void privateKeyManager_newKey_messageLite_works() throws Exception {
    EcdsaKeyFormat keyFormat =
        EcdsaKeyFormat.newBuilder()
            .setParams(
                EcdsaParams.newBuilder()
                    .setHashType(HashType.SHA256)
                    .setCurve(EllipticCurveType.NIST_P256)
                    .setEncoding(EcdsaSignatureEncoding.IEEE_P1363))
            .build();

    EcdsaPrivateKey key1 = (EcdsaPrivateKey) privateKeyManager.newKey(keyFormat);
    EcdsaPrivateKey key2 = (EcdsaPrivateKey) privateKeyManager.newKey(keyFormat);
    assertThat(key1.getKeyValue().size()).isEqualTo(33);
    assertThat(key1.getKeyValue()).isNotEqualTo(key2.getKeyValue());
    assertThat(key1.getPublicKey().getParams()).isEqualTo(keyFormat.getParams());
  }

  @Test
  public void privateKeyManager_newKeyData_works() throws Exception {
    EcdsaKeyFormat keyFormat =
        EcdsaKeyFormat.newBuilder()
            .setParams(
                EcdsaParams.newBuilder()
                    .setHashType(HashType.SHA256)
                    .setCurve(EllipticCurveType.NIST_P256)
                    .setEncoding(EcdsaSignatureEncoding.IEEE_P1363))
            .build();

    KeyData keyData1 = privateKeyManager.newKeyData(keyFormat.toByteString());
    KeyData keyData2 = privateKeyManager.newKeyData(keyFormat.toByteString());
    assertThat(keyData1.getKeyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PRIVATE);

    assertThat(keyData1.getTypeUrl())
        .isEqualTo("type.googleapis.com/google.crypto.tink.EcdsaPrivateKey");
    EcdsaPrivateKey protoKey1 =
        EcdsaPrivateKey.parseFrom(keyData1.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    EcdsaPrivateKey protoKey2 =
        EcdsaPrivateKey.parseFrom(keyData2.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(protoKey1.getKeyValue().size()).isEqualTo(33);
    assertThat(protoKey1.getKeyValue()).isNotEqualTo(protoKey2.getKeyValue());
    assertThat(protoKey1.getPublicKey().getParams()).isEqualTo(keyFormat.getParams());
  }

  @Test
  public void privateKeyManager_doesSupport_works() throws Exception {
    assertTrue(
        privateKeyManager.doesSupport("type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"));
    assertFalse(
        privateKeyManager.doesSupport("type.googleapis.com/google.crypto.tink.SomeOtherKey"));
  }

  @Test
  public void privateKeyManager_getKeyType_works() throws Exception {

    assertThat(privateKeyManager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.EcdsaPrivateKey");
  }

  @Test
  public void privateKeyManager_getVersion_works() throws Exception {
    assertThat(privateKeyManager.getVersion()).isEqualTo(0);
  }

  @Test
  public void privateKeyManager_getPrimitiveClass_works() throws Exception {
    assertThat(privateKeyManager.getPrimitiveClass()).isEqualTo(PublicKeySign.class);
  }

  @Test
  public void privateKeyManager_getPublicKey_works() throws Exception {
    KeyData publicKeyData = privateKeyManager.getPublicKeyData(getProtoPrivateKey().toByteString());
    assertThat(publicKeyData.getTypeUrl())
        .isEqualTo("type.googleapis.com/google.crypto.tink.EcdsaPublicKey");
    assertThat(publicKeyData.getKeyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);

    EcdsaPublicKey publicKey =
        EcdsaPublicKey.parseFrom(
            publicKeyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(publicKey).isEqualTo(getProtoPrivateKey().getPublicKey());
  }

  @Test
  public void privateKeyManager_getPublicKey_notAPrivateKey_throws() throws Exception {
    // To test how LegacyKeyManagerImpl.createPrivateKeyManager fails when we use it with a
    // symmetric key, we simply use it with the same HmacKey as above.
    PrivateKeyManager<Mac> privateKeyManager =
        LegacyKeyManagerImpl.createPrivateKeyManager(
            "type.googleapis.com/google.crypto.tink.HmacKey", Mac.class, HmacKey.parser());

    HmacKey key =
        HmacKey.newBuilder()
            .setVersion(0)
            .setParams(HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16))
            .setKeyValue(
                ByteString.copyFrom(
                    Hex.decode("816aa4c3ee066310ac1e6666cf830c375355c3c8ba18cfe1f50a48c988b46272")))
            .build();

    GeneralSecurityException exception =
        assertThrows(
            GeneralSecurityException.class,
            () -> privateKeyManager.getPublicKeyData(key.toByteString()));
    assertThat(exception).hasMessageThat().contains("Key not private key");
  }
}
