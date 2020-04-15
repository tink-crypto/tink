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
import com.google.crypto.tink.proto.RsaSsaPssKeyFormat;
import com.google.crypto.tink.proto.RsaSsaPssParams;
import com.google.crypto.tink.proto.RsaSsaPssPrivateKey;
import com.google.crypto.tink.proto.RsaSsaPssPublicKey;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.RsaSsaPssSignJce;
import com.google.crypto.tink.subtle.RsaSsaPssVerifyJce;
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
 * This key manager generates new {@code RsaSsaPssPrivateKey} keys and produces new instances of
 * {@code RsaSsaPssSignJce}.
 */
class RsaSsaPssSignKeyManager
    extends PrivateKeyTypeManager<RsaSsaPssPrivateKey, RsaSsaPssPublicKey> {
  private static final byte[] TEST_MESSAGE =
      "Tink and Wycheproof.".getBytes(Charset.forName("UTF-8"));

  public RsaSsaPssSignKeyManager() {
    super(
        RsaSsaPssPrivateKey.class,
        RsaSsaPssPublicKey.class,
        new PrimitiveFactory<PublicKeySign, RsaSsaPssPrivateKey>(PublicKeySign.class) {
          @Override
          public PublicKeySign getPrimitive(RsaSsaPssPrivateKey keyProto)
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
    return "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey";
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public RsaSsaPssPublicKey getPublicKey(RsaSsaPssPrivateKey privKeyProto)
      throws GeneralSecurityException {
    return privKeyProto.getPublicKey();
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.ASYMMETRIC_PRIVATE;
  }

  @Override
  public RsaSsaPssPrivateKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    return RsaSsaPssPrivateKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public void validateKey(RsaSsaPssPrivateKey keyProto) throws GeneralSecurityException {
    Validators.validateVersion(keyProto.getVersion(), getVersion());
    Validators.validateRsaModulusSize(
        new BigInteger(1, keyProto.getPublicKey().getN().toByteArray()).bitLength());
    SigUtil.validateRsaSsaPssParams(keyProto.getPublicKey().getParams());
  }

  @Override
  public KeyFactory<RsaSsaPssKeyFormat, RsaSsaPssPrivateKey> keyFactory() {
    return new KeyFactory<RsaSsaPssKeyFormat, RsaSsaPssPrivateKey>(RsaSsaPssKeyFormat.class) {
      @Override
      public void validateKeyFormat(RsaSsaPssKeyFormat format) throws GeneralSecurityException {
        SigUtil.validateRsaSsaPssParams(format.getParams());
        Validators.validateRsaModulusSize(format.getModulusSizeInBits());
      }

      @Override
      public RsaSsaPssKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return RsaSsaPssKeyFormat.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public RsaSsaPssPrivateKey createKey(RsaSsaPssKeyFormat format)
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
                .setVersion(getVersion())
                .setParams(params)
                .setE(ByteString.copyFrom(pubKey.getPublicExponent().toByteArray()))
                .setN(ByteString.copyFrom(pubKey.getModulus().toByteArray()))
                .build();

        // Creates RsaSsaPssPrivateKey.
        return RsaSsaPssPrivateKey.newBuilder()
            .setVersion(getVersion())
            .setPublicKey(pssPubKey)
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
   * Registers the {@link RsaSsaPssSignKeyManager} and the {@link RsaSsaPssVerifyKeyManager}
   * with the registry, so that the the RsaSsaPss-Keys can be used with Tink.
   */
  public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerAsymmetricKeyManagers(
        new RsaSsaPssSignKeyManager(), new RsaSsaPssVerifyKeyManager(), newKeyAllowed);
  }
}
