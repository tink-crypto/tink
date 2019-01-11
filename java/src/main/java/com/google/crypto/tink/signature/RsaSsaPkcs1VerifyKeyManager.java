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
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.proto.Empty;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.RsaSsaPkcs1VerifyJce;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

/**
 * This key manager produces new instances of {@code RsaSsaPkcs1VerifyJce}. It doesn't support key
 * generation.
 */
class RsaSsaPkcs1VerifyKeyManager
    extends KeyManagerBase<PublicKeyVerify, RsaSsaPkcs1PublicKey, Empty> {
  public RsaSsaPkcs1VerifyKeyManager() {
    super(PublicKeyVerify.class, RsaSsaPkcs1PublicKey.class, Empty.class, TYPE_URL);
  }

  private static final int VERSION = 0;
  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey";

  @Override
  public PublicKeyVerify getPrimitiveFromKey(RsaSsaPkcs1PublicKey keyProto)
      throws GeneralSecurityException {
    validateKey(keyProto);
    KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("RSA");
    BigInteger modulus = new BigInteger(1, keyProto.getN().toByteArray());
    BigInteger exponent = new BigInteger(1, keyProto.getE().toByteArray());
    RSAPublicKey publicKey =
        (RSAPublicKey) kf.generatePublic(new RSAPublicKeySpec(modulus, exponent));
    return new RsaSsaPkcs1VerifyJce(
        publicKey, SigUtil.toHashType(keyProto.getParams().getHashType()));
  }

  @Override
  public RsaSsaPkcs1PublicKey newKeyFromFormat(Empty serializedKeyFormat)
      throws GeneralSecurityException {
    throw new GeneralSecurityException("Not implemented");
  }

  @Override
  public int getVersion() {
    return VERSION;
  }

  @Override
  protected KeyMaterialType keyMaterialType() {
    return KeyMaterialType.ASYMMETRIC_PUBLIC;
  }

  @Override
  protected RsaSsaPkcs1PublicKey parseKeyProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return RsaSsaPkcs1PublicKey.parseFrom(byteString);
  }

  @Override
  protected Empty parseKeyFormatProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return Empty.parseFrom(byteString);
  }

  @Override
  protected void validateKey(RsaSsaPkcs1PublicKey pubKey) throws GeneralSecurityException {
    Validators.validateVersion(pubKey.getVersion(), VERSION);
    Validators.validateRsaModulusSize((new BigInteger(1, pubKey.getN().toByteArray())).bitLength());
    SigUtil.validateRsaSsaPkcs1Params(pubKey.getParams());
  }

  @Override
  protected void validateKeyFormat(Empty unused) {}
}
