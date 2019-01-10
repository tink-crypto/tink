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
import com.google.crypto.tink.proto.RsaSsaPssParams;
import com.google.crypto.tink.proto.RsaSsaPssPublicKey;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.RsaSsaPssVerifyJce;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

/**
 * This key manager produces new instances of {@code RsaSsaPssVerifyJce}. It doesn't support key
 * generation.
 */
class RsaSsaPssVerifyKeyManager extends KeyManagerBase<PublicKeyVerify, RsaSsaPssPublicKey, Empty> {
  public RsaSsaPssVerifyKeyManager() {
    super(PublicKeyVerify.class, RsaSsaPssPublicKey.class, Empty.class, TYPE_URL);
  }

  public static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey";

  private static final int VERSION = 0;

  @Override
  public PublicKeyVerify getPrimitiveFromKey(RsaSsaPssPublicKey keyProto)
      throws GeneralSecurityException {
    KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("RSA");
    BigInteger modulus = new BigInteger(1, keyProto.getN().toByteArray());
    BigInteger exponent = new BigInteger(1, keyProto.getE().toByteArray());
    RSAPublicKey publicKey =
        (RSAPublicKey) kf.generatePublic(new RSAPublicKeySpec(modulus, exponent));
    RsaSsaPssParams params = keyProto.getParams();
    return new RsaSsaPssVerifyJce(
        publicKey,
        SigUtil.toHashType(params.getSigHash()),
        SigUtil.toHashType(params.getMgf1Hash()),
        params.getSaltLength());
  }

  @Override
  protected RsaSsaPssPublicKey newKeyFromFormat(Empty unused) throws GeneralSecurityException {
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
  protected RsaSsaPssPublicKey parseKeyProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return RsaSsaPssPublicKey.parseFrom(byteString);
  }

  @Override
  protected Empty parseKeyFormatProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return Empty.parseFrom(byteString);
  }

  @Override
  protected void validateKey(RsaSsaPssPublicKey pubKey) throws GeneralSecurityException {
    Validators.validateVersion(pubKey.getVersion(), VERSION);
    Validators.validateRsaModulusSize(new BigInteger(1, pubKey.getN().toByteArray()).bitLength());
    SigUtil.validateRsaSsaPssParams(pubKey.getParams());
  }

  @Override
  protected void validateKeyFormat(Empty unused) throws GeneralSecurityException {}
}
