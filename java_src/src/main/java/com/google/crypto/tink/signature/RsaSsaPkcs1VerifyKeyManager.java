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

import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.signature.internal.SigUtil;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.RsaSsaPkcs1VerifyJce;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

/**
 * This key manager produces new instances of {@code RsaSsaPkcs1VerifyJce}. It doesn't support key
 * generation.
 */
class RsaSsaPkcs1VerifyKeyManager extends KeyTypeManager<RsaSsaPkcs1PublicKey> {
  public RsaSsaPkcs1VerifyKeyManager() {
    super(
        RsaSsaPkcs1PublicKey.class,
        new KeyTypeManager.PrimitiveFactory<PublicKeyVerify, RsaSsaPkcs1PublicKey>(
            PublicKeyVerify.class) {
          @Override
          public PublicKeyVerify getPrimitive(RsaSsaPkcs1PublicKey keyProto)
              throws GeneralSecurityException {
            java.security.KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("RSA");
            BigInteger modulus = new BigInteger(1, keyProto.getN().toByteArray());
            BigInteger exponent = new BigInteger(1, keyProto.getE().toByteArray());
            RSAPublicKey publicKey =
                (RSAPublicKey) kf.generatePublic(new RSAPublicKeySpec(modulus, exponent));
            return new RsaSsaPkcs1VerifyJce(
                publicKey, SigUtil.toHashType(keyProto.getParams().getHashType()));
          }
        });
  }

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey";
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.ASYMMETRIC_PUBLIC;
  }

  @Override
  public RsaSsaPkcs1PublicKey parseKey(ByteString byteString)
      throws InvalidProtocolBufferException {
    return RsaSsaPkcs1PublicKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public void validateKey(RsaSsaPkcs1PublicKey pubKey) throws GeneralSecurityException {
    Validators.validateVersion(pubKey.getVersion(), getVersion());
    Validators.validateRsaModulusSize((new BigInteger(1, pubKey.getN().toByteArray())).bitLength());
    Validators.validateRsaPublicExponent(new BigInteger(1, pubKey.getE().toByteArray()));
    SigUtil.validateRsaSsaPkcs1Params(pubKey.getParams());
  }

  @Override
  public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
    return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;
  };
}
