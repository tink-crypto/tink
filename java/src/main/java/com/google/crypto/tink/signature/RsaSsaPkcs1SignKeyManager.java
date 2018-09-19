// Copyright 2018 Google Inc.
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

package com.google.crypto.tink.signature;

import com.google.crypto.tink.PrivateKeyManager;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.RsaSsaPkcs1KeyFormat;
import com.google.crypto.tink.proto.RsaSsaPkcs1Params;
import com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.RsaSsaPkcs1SignJce;
import com.google.crypto.tink.subtle.RsaSsaPkcs1VerifyJce;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * This key manager generates new {@code RsaSsaPkcs1PrivateKey} keys and produces new instances of
 * {@code RsaSsaPkcs1SignJce}.
 */
class RsaSsaPkcs1SignKeyManager implements PrivateKeyManager<PublicKeySign> {
  /** Type url that this manager supports */
  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey";

  /** Current version of this key manager. Keys with greater version are not supported. */
  private static final int VERSION = 0;

  private static final Charset UTF_8 = Charset.forName("UTF-8");

  /** Test message. */
  private static final byte[] TEST_MESSAGE = "Tink and Wycheproof.".getBytes(UTF_8);

  /** @param serializedKey serialized {@code RsaSsaPkcs1PrivateKey} proto */
  @Override
  public PublicKeySign getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      RsaSsaPkcs1PrivateKey privKeyProto = RsaSsaPkcs1PrivateKey.parseFrom(serializedKey);
      return getPrimitive(privKeyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized RsaSsaPkcs1PrivateKey proto", e);
    }
  }

  /** @param key {@code RsaSsaPkcs1PrivateKey} proto */
  @Override
  public PublicKeySign getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof RsaSsaPkcs1PrivateKey)) {
      throw new GeneralSecurityException("expected RsaSsaPkcs1PrivateKey proto");
    }
    RsaSsaPkcs1PrivateKey keyProto = (RsaSsaPkcs1PrivateKey) key;
    validateKey(keyProto);
    KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("RSA");
    RSAPrivateCrtKey privateKey =
        (RSAPrivateCrtKey)
            kf.generatePrivate(
                new RSAPrivateCrtKeySpec(
                    new BigInteger(1, keyProto.getPublicKey().getN().toByteArray()),
                    new BigInteger(1, keyProto.getPublicKey().getE().toByteArray()),
                    new BigInteger(1, keyProto.getD().toByteArray()),
                    new BigInteger(1, keyProto.getP().toByteArray()),
                    new BigInteger(1, keyProto.getQ().toByteArray()),
                    new BigInteger(1, keyProto.getDp().toByteArray()),
                    new BigInteger(1, keyProto.getDq().toByteArray()),
                    new BigInteger(1, keyProto.getCrt().toByteArray())));
    // Sign and verify a test message to make sure that the key is correct.
    RsaSsaPkcs1SignJce signer =
        new RsaSsaPkcs1SignJce(
            privateKey, SigUtil.toHashType(keyProto.getPublicKey().getParams().getHashType()));
    RSAPublicKey publicKey =
        (RSAPublicKey)
            kf.generatePublic(
                new RSAPublicKeySpec(
                    new BigInteger(1, keyProto.getPublicKey().getN().toByteArray()),
                    new BigInteger(1, keyProto.getPublicKey().getE().toByteArray())));
    RsaSsaPkcs1VerifyJce verifier =
        new RsaSsaPkcs1VerifyJce(
            publicKey, SigUtil.toHashType(keyProto.getPublicKey().getParams().getHashType()));
    try {
      verifier.verify(signer.sign(TEST_MESSAGE), TEST_MESSAGE);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(
          "Security bug: signing with private key followed by verifying with public key failed"
              + e);
    }
    return signer;
  }

  /**
   * @param serializedKeyFormat serialized {@code RsaSsaPkcs1KeyFormat} proto
   * @return new {@code RsaSsaPkcs1PrivateKey} proto
   */
  @Override
  public MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    try {
      RsaSsaPkcs1KeyFormat pkcs1KeyFormat = RsaSsaPkcs1KeyFormat.parseFrom(serializedKeyFormat);
      return newKey(pkcs1KeyFormat);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected RsaSsaPkcs1KeyFormat proto", e);
    }
  }

  /**
   * @param keyFormat {@code RsaSsaPkcs1KeyFormat} proto
   * @return new {@code RsaSsaPkcs1PrivateKey} proto
   */
  @Override
  public MessageLite newKey(MessageLite keyFormat) throws GeneralSecurityException {
    if (!(keyFormat instanceof RsaSsaPkcs1KeyFormat)) {
      throw new GeneralSecurityException("expected RsaSsaPkcs1KeyFormat proto");
    }
    RsaSsaPkcs1KeyFormat format = (RsaSsaPkcs1KeyFormat) keyFormat;
    RsaSsaPkcs1Params params = format.getParams();
    Validators.validateRsaModulusSize(format.getModulusSizeInBits());
    Validators.validateSignatureHash(SigUtil.toHashType(params.getHashType()));
    KeyPairGenerator keyGen = EngineFactory.KEY_PAIR_GENERATOR.getInstance("RSA");
    RSAKeyGenParameterSpec spec =
        new RSAKeyGenParameterSpec(
            format.getModulusSizeInBits(),
            new BigInteger(1, format.getPublicExponent().toByteArray()));
    keyGen.initialize(spec);
    KeyPair keyPair = keyGen.generateKeyPair();
    RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();

    // Creates RsaSsaPkcs1PublicKey.
    RsaSsaPkcs1PublicKey pkcs1PubKey =
        RsaSsaPkcs1PublicKey.newBuilder()
            .setVersion(VERSION)
            .setParams(params)
            .setE(ByteString.copyFrom(pubKey.getPublicExponent().toByteArray()))
            .setN(ByteString.copyFrom(pubKey.getModulus().toByteArray()))
            .build();

    // Creates RsaSsaPkcs1PrivateKey.
    return RsaSsaPkcs1PrivateKey.newBuilder()
        .setVersion(VERSION)
        .setPublicKey(pkcs1PubKey)
        .setD(ByteString.copyFrom(privKey.getPrivateExponent().toByteArray()))
        .setP(ByteString.copyFrom(privKey.getPrimeP().toByteArray()))
        .setQ(ByteString.copyFrom(privKey.getPrimeQ().toByteArray()))
        .setDp(ByteString.copyFrom(privKey.getPrimeExponentP().toByteArray()))
        .setDq(ByteString.copyFrom(privKey.getPrimeExponentQ().toByteArray()))
        .setCrt(ByteString.copyFrom(privKey.getCrtCoefficient().toByteArray()))
        .build();
  }

  /**
   * @param serializedKeyFormat serialized {@code RsaSsaPkcs1KeyFormat} proto
   * @return {@code KeyData} with a new {@code RsaSsaPkcs1PrivateKey} proto
   */
  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    RsaSsaPkcs1PrivateKey key = (RsaSsaPkcs1PrivateKey) newKey(serializedKeyFormat);
    return KeyData.newBuilder()
        .setTypeUrl(TYPE_URL)
        .setValue(key.toByteString())
        .setKeyMaterialType(KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE)
        .build();
  }

  @Override
  public KeyData getPublicKeyData(ByteString serializedKey) throws GeneralSecurityException {
    try {
      RsaSsaPkcs1PrivateKey privKeyProto = RsaSsaPkcs1PrivateKey.parseFrom(serializedKey);
      return KeyData.newBuilder()
          .setTypeUrl(RsaSsaPkcs1VerifyKeyManager.TYPE_URL)
          .setValue(privKeyProto.getPublicKey().toByteString())
          .setKeyMaterialType(KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC)
          .build();
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized RsaSsaPkcs1PrivateKey proto", e);
    }
  }

  @Override
  public String getKeyType() {
    return TYPE_URL;
  }

  @Override
  public boolean doesSupport(String typeUrl) {
    return TYPE_URL.equals(typeUrl);
  }

  @Override
  public int getVersion() {
    return VERSION;
  }

  private void validateKey(RsaSsaPkcs1PrivateKey privKey) throws GeneralSecurityException {
    Validators.validateVersion(privKey.getVersion(), VERSION);
    Validators.validateRsaModulusSize(
        (new BigInteger(1, privKey.getPublicKey().getN().toByteArray())).bitLength());
    Validators.validateSignatureHash(
        SigUtil.toHashType(privKey.getPublicKey().getParams().getHashType()));
  }
}
