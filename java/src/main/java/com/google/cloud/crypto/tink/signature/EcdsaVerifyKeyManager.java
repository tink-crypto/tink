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
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.cloud.crypto.tink.signature;

import com.google.cloud.crypto.tink.EcdsaProto.EcdsaParams;
import com.google.cloud.crypto.tink.EcdsaProto.EcdsaPublicKey;
import com.google.cloud.crypto.tink.KeyManager;
import com.google.cloud.crypto.tink.PublicKeyVerify;
import com.google.cloud.crypto.tink.TinkProto.KeyFormat;
import com.google.cloud.crypto.tink.subtle.EcdsaVerifyJce;
import com.google.cloud.crypto.tink.subtle.Util;
import com.google.protobuf.Any;
import com.google.protobuf.InvalidProtocolBufferException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;

final class EcdsaVerifyKeyManager implements KeyManager<PublicKeyVerify> {
  private static final String ECDSA_PUBLIC_KEY_TYPE =
      "type.googleapis.com/google.cloud.crypto.tink.EcdsaPublicKey";
  /**
   * Current version of this key manager.
   * Keys with greater version are not supported.
   */
  private static final int VERSION = 0;

  @Override
  public PublicKeyVerify getPrimitive(Any proto) throws GeneralSecurityException {
    EcdsaPublicKey pubKey;
    try {
      pubKey = proto.unpack(EcdsaPublicKey.class);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException(e);
    }
    validateKey(pubKey);
    ECParameterSpec ecParams = SigUtil.getCurveSpec(pubKey.getParams().getCurve());
    BigInteger pubX = new BigInteger(1, pubKey.getX().toByteArray());
    BigInteger pubY = new BigInteger(1, pubKey.getY().toByteArray());
    ECPoint w = new ECPoint(pubX, pubY);
    ECPublicKeySpec spec = new ECPublicKeySpec(w, ecParams);
    KeyFactory kf = KeyFactory.getInstance("EC");
    return new EcdsaVerifyJce((ECPublicKey) kf.generatePublic(spec),
        SigUtil.hashToEcdsaAlgorithmName(pubKey.getParams().getHashType()));
  }

  @Override
  public Any newKey(KeyFormat format) throws GeneralSecurityException {
    throw new GeneralSecurityException("Not implemented");
  }

  @Override
  public boolean doesSupport(String typeUrl) {
    return ECDSA_PUBLIC_KEY_TYPE.equals(typeUrl);
  }

  private void validateKey(EcdsaPublicKey pubKey) throws GeneralSecurityException {
    Util.validateVersion(pubKey.getVersion(), VERSION);
    if (!SigUtil.validateEcdsaParams(pubKey.getParams())) {
      throw new GeneralSecurityException("Invalid Ecdsa's parameters");
    }
  }
}
