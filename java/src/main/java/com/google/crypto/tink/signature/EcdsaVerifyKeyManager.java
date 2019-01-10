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

package com.google.crypto.tink.signature;

import com.google.crypto.tink.KeyManagerBase;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.proto.EcdsaPublicKey;
import com.google.crypto.tink.proto.Empty;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.EcdsaVerifyJce;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;

/**
 * This key manager produces new instances of {@code EcdsaVerifyJce}. It doesn't support key
 * generation.
 */
class EcdsaVerifyKeyManager extends KeyManagerBase<PublicKeyVerify, EcdsaPublicKey, Empty> {
  public EcdsaVerifyKeyManager() {
    super(PublicKeyVerify.class, EcdsaPublicKey.class, Empty.class, TYPE_URL);
  }

  public static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.EcdsaPublicKey";
  /** Current version of this key manager. Keys with greater version are not supported. */
  private static final int VERSION = 0;

  @Override
  public PublicKeyVerify getPrimitiveFromKey(EcdsaPublicKey keyProto)
      throws GeneralSecurityException {
    ECPublicKey publicKey =
        EllipticCurves.getEcPublicKey(
            SigUtil.toCurveType(keyProto.getParams().getCurve()),
            keyProto.getX().toByteArray(),
            keyProto.getY().toByteArray());
    return new EcdsaVerifyJce(
        publicKey,
        SigUtil.toHashType(keyProto.getParams().getHashType()),
        SigUtil.toEcdsaEncoding(keyProto.getParams().getEncoding()));
  }

  @Override
  public EcdsaPublicKey newKeyFromFormat(Empty unused) throws GeneralSecurityException {
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
  protected EcdsaPublicKey parseKeyProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return EcdsaPublicKey.parseFrom(byteString);
  }

  @Override
  protected Empty parseKeyFormatProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return Empty.parseFrom(byteString);
  }

  @Override
  protected void validateKey(EcdsaPublicKey pubKey) throws GeneralSecurityException {
    Validators.validateVersion(pubKey.getVersion(), VERSION);
    SigUtil.validateEcdsaParams(pubKey.getParams());
  }

  @Override
  protected void validateKeyFormat(Empty unused) throws GeneralSecurityException {}
}
