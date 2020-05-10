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

import com.google.crypto.tink.PrivateKeyTypeManager;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.RsaSsaPkcs1KeyFormat;
import com.google.crypto.tink.proto.RsaSsaPkcs1Params;
import com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.RsaSsaPkcs1SignJce;
import com.google.crypto.tink.subtle.RsaSsaPkcs1VerifyJce;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
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
 * This key manager generates new {@code RsaSsaPkcs1PrivateKey} keys and produces new instances of
 * {@code RsaSsaPkcs1SignJce}.
 */
class RsaSsaPkcs1SignKeyManager
    extends PrivateKeyTypeManager<RsaSsaPkcs1PrivateKey, RsaSsaPkcs1PublicKey> {
  private static final byte[] TEST_MESSAGE =
      "Tink and Wycheproof.".getBytes(Charset.forName("UTF-8"));

  public RsaSsaPkcs1SignKeyManager() {
    super(
        RsaSsaPkcs1PrivateKey.class,
        RsaSsaPkcs1PublicKey.class,
        new PrimitiveFactory<PublicKeySign, RsaSsaPkcs1PrivateKey>(PublicKeySign.class) {
          @Override
          public PublicKeySign getPrimitive(RsaSsaPkcs1PrivateKey keyProto)
              throws GeneralSecurityException {
            java.security.KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("RSA");
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
                    privateKey,
                    SigUtil.toHashType(keyProto.getPublicKey().getParams().getHashType()));
            RSAPublicKey publicKey =
                (RSAPublicKey)
                    kf.generatePublic(
                        new RSAPublicKeySpec(
                            new BigInteger(1, keyProto.getPublicKey().getN().toByteArray()),
                            new BigInteger(1, keyProto.getPublicKey().getE().toByteArray())));
            RsaSsaPkcs1VerifyJce verifier =
                new RsaSsaPkcs1VerifyJce(
                    publicKey,
                    SigUtil.toHashType(keyProto.getPublicKey().getParams().getHashType()));
            try {
              verifier.verify(signer.sign(TEST_MESSAGE), TEST_MESSAGE);
            } catch (GeneralSecurityException e) {
              throw new RuntimeException(
                  "Security bug: signing with private key followed by verifying with public key"
                      + " failed"
                      + e);
            }
            return signer;
          }
        });
  }

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey";
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public RsaSsaPkcs1PublicKey getPublicKey(RsaSsaPkcs1PrivateKey privKeyProto)
      throws GeneralSecurityException {
    return privKeyProto.getPublicKey();
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.ASYMMETRIC_PRIVATE;
  }

  @Override
  public RsaSsaPkcs1PrivateKey parseKey(ByteString byteString)
      throws InvalidProtocolBufferException {
    return RsaSsaPkcs1PrivateKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public void validateKey(RsaSsaPkcs1PrivateKey privKey) throws GeneralSecurityException {
    Validators.validateVersion(privKey.getVersion(), getVersion());
    Validators.validateRsaModulusSize(
        new BigInteger(1, privKey.getPublicKey().getN().toByteArray()).bitLength());
    SigUtil.validateRsaSsaPkcs1Params(privKey.getPublicKey().getParams());
  }

  @Override
  public KeyFactory<RsaSsaPkcs1KeyFormat, RsaSsaPkcs1PrivateKey> keyFactory() {
    return new KeyFactory<RsaSsaPkcs1KeyFormat, RsaSsaPkcs1PrivateKey>(RsaSsaPkcs1KeyFormat.class) {
      @Override
      public void validateKeyFormat(RsaSsaPkcs1KeyFormat keyFormat)
          throws GeneralSecurityException {
        SigUtil.validateRsaSsaPkcs1Params(keyFormat.getParams());
        Validators.validateRsaModulusSize(keyFormat.getModulusSizeInBits());
      }

      @Override
      public RsaSsaPkcs1KeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return RsaSsaPkcs1KeyFormat.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public RsaSsaPkcs1PrivateKey createKey(RsaSsaPkcs1KeyFormat format)
          throws GeneralSecurityException {
        RsaSsaPkcs1Params params = format.getParams();
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
                .setVersion(getVersion())
                .setParams(params)
                .setE(ByteString.copyFrom(pubKey.getPublicExponent().toByteArray()))
                .setN(ByteString.copyFrom(pubKey.getModulus().toByteArray()))
                .build();

        // Creates RsaSsaPkcs1PrivateKey.
        return RsaSsaPkcs1PrivateKey.newBuilder()
            .setVersion(getVersion())
            .setPublicKey(pkcs1PubKey)
            .setD(ByteString.copyFrom(privKey.getPrivateExponent().toByteArray()))
            .setP(ByteString.copyFrom(privKey.getPrimeP().toByteArray()))
            .setQ(ByteString.copyFrom(privKey.getPrimeQ().toByteArray()))
            .setDp(ByteString.copyFrom(privKey.getPrimeExponentP().toByteArray()))
            .setDq(ByteString.copyFrom(privKey.getPrimeExponentQ().toByteArray()))
            .setCrt(ByteString.copyFrom(privKey.getCrtCoefficient().toByteArray()))
            .build();
      }
    };
  }

  /**
   * Registers the {@link RsaSsaPkcs1SignKeyManager} and the {@link RsaSsaPkcs1VerifyKeyManager}
   * with the registry, so that the the RsaSsaPkcs1-Keys can be used with Tink.
   */
  public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerAsymmetricKeyManagers(
        new RsaSsaPkcs1SignKeyManager(), new RsaSsaPkcs1VerifyKeyManager(), newKeyAllowed);
  }
}
