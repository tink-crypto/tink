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

import com.google.crypto.tink.KeyManagerBase;
import com.google.crypto.tink.PrivateKeyManager;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.RsaSsaPssKeyFormat;
import com.google.crypto.tink.proto.RsaSsaPssParams;
import com.google.crypto.tink.proto.RsaSsaPssPrivateKey;
import com.google.crypto.tink.proto.RsaSsaPssPublicKey;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.RsaSsaPssSignJce;
import com.google.crypto.tink.subtle.RsaSsaPssVerifyJce;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
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
 * This key manager generates new {@code RsaSsaPssPrivateKey} keys and produces new instances of
 * {@code RsaSsaPssSignJce}.
 */
class RsaSsaPssSignKeyManager
    extends KeyManagerBase<PublicKeySign, RsaSsaPssPrivateKey, RsaSsaPssKeyFormat>
    implements PrivateKeyManager<PublicKeySign> {
  public RsaSsaPssSignKeyManager() {
    super(PublicKeySign.class, RsaSsaPssPrivateKey.class, RsaSsaPssKeyFormat.class, TYPE_URL);
  }

  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey";

  private static final int VERSION = 0;

  private static final Charset UTF_8 = Charset.forName("UTF-8");

  /** Test message. */
  private static final byte[] TEST_MESSAGE = "Tink and Wycheproof.".getBytes(UTF_8);

  @Override
  public PublicKeySign getPrimitiveFromKey(RsaSsaPssPrivateKey keyProto)
      throws GeneralSecurityException {
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
    RsaSsaPssParams params = keyProto.getPublicKey().getParams();
    // Sign and verify a test message to make sure that the key is correct.
    RsaSsaPssSignJce signer =
        new RsaSsaPssSignJce(
            privateKey,
            SigUtil.toHashType(params.getSigHash()),
            SigUtil.toHashType(params.getMgf1Hash()),
            params.getSaltLength());
    RSAPublicKey publicKey =
        (RSAPublicKey)
            kf.generatePublic(
                new RSAPublicKeySpec(
                    new BigInteger(1, keyProto.getPublicKey().getN().toByteArray()),
                    new BigInteger(1, keyProto.getPublicKey().getE().toByteArray())));
    RsaSsaPssVerifyJce verifier =
        new RsaSsaPssVerifyJce(
            publicKey,
            SigUtil.toHashType(params.getSigHash()),
            SigUtil.toHashType(params.getMgf1Hash()),
            params.getSaltLength());
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
   * @param serializedKeyFormat serialized {@code RsaSsaPssKeyFormat} proto
   * @return new {@code RsaSsaPssPrivateKey} proto
   */
  @Override
  protected RsaSsaPssPrivateKey newKeyFromFormat(RsaSsaPssKeyFormat format)
      throws GeneralSecurityException {
    RsaSsaPssParams params = format.getParams();
    Validators.validateRsaModulusSize(format.getModulusSizeInBits());
    Validators.validateSignatureHash(SigUtil.toHashType(params.getSigHash()));
    KeyPairGenerator keyGen = EngineFactory.KEY_PAIR_GENERATOR.getInstance("RSA");
    RSAKeyGenParameterSpec spec =
        new RSAKeyGenParameterSpec(
            format.getModulusSizeInBits(),
            new BigInteger(1, format.getPublicExponent().toByteArray()));
    keyGen.initialize(spec);
    KeyPair keyPair = keyGen.generateKeyPair();
    RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();

    // Creates RsaSsaPssPublicKey.
    RsaSsaPssPublicKey pssPubKey =
        RsaSsaPssPublicKey.newBuilder()
            .setVersion(VERSION)
            .setParams(params)
            .setE(ByteString.copyFrom(pubKey.getPublicExponent().toByteArray()))
            .setN(ByteString.copyFrom(pubKey.getModulus().toByteArray()))
            .build();

    // Creates RsaSsaPssPrivateKey.
    return RsaSsaPssPrivateKey.newBuilder()
        .setVersion(VERSION)
        .setPublicKey(pssPubKey)
        .setD(ByteString.copyFrom(privKey.getPrivateExponent().toByteArray()))
        .setP(ByteString.copyFrom(privKey.getPrimeP().toByteArray()))
        .setQ(ByteString.copyFrom(privKey.getPrimeQ().toByteArray()))
        .setDp(ByteString.copyFrom(privKey.getPrimeExponentP().toByteArray()))
        .setDq(ByteString.copyFrom(privKey.getPrimeExponentQ().toByteArray()))
        .setCrt(ByteString.copyFrom(privKey.getCrtCoefficient().toByteArray()))
        .build();
  }

  @Override
  public KeyData getPublicKeyData(ByteString serializedKey) throws GeneralSecurityException {
    try {
      RsaSsaPssPrivateKey privKeyProto = RsaSsaPssPrivateKey.parseFrom(serializedKey);
      return KeyData.newBuilder()
          .setTypeUrl(RsaSsaPssVerifyKeyManager.TYPE_URL)
          .setValue(privKeyProto.getPublicKey().toByteString())
          .setKeyMaterialType(KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC)
          .build();
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized RsaSsaPssPrivateKey proto", e);
    }
  }

  @Override
  protected KeyMaterialType keyMaterialType() {
    return KeyMaterialType.ASYMMETRIC_PRIVATE;
  }

  @Override
  protected RsaSsaPssPrivateKey parseKeyProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return RsaSsaPssPrivateKey.parseFrom(byteString);
  }

  @Override
  protected RsaSsaPssKeyFormat parseKeyFormatProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return RsaSsaPssKeyFormat.parseFrom(byteString);
  }

  @Override
  public int getVersion() {
    return VERSION;
  }

  @Override
  protected void validateKeyFormat(RsaSsaPssKeyFormat format) throws GeneralSecurityException {
    SigUtil.validateRsaSsaPssParams(format.getParams());
    Validators.validateRsaModulusSize(format.getModulusSizeInBits());
  }

  @Override
  protected void validateKey(RsaSsaPssPrivateKey privKey) throws GeneralSecurityException {
    Validators.validateVersion(privKey.getVersion(), VERSION);
    Validators.validateRsaModulusSize(
        new BigInteger(1, privKey.getPublicKey().getN().toByteArray()).bitLength());
    SigUtil.validateRsaSsaPssParams(privKey.getPublicKey().getParams());
  }
}
