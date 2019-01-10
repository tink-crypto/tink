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
import com.google.crypto.tink.PrivateKeyManager;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.proto.EcdsaKeyFormat;
import com.google.crypto.tink.proto.EcdsaParams;
import com.google.crypto.tink.proto.EcdsaPrivateKey;
import com.google.crypto.tink.proto.EcdsaPublicKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.EcdsaSignJce;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

/**
 * This key manager generates new {@code EcdsaPrivateKey} keys and produces new instances of {@code
 * EcdsaSignJce}.
 */
class EcdsaSignKeyManager
    extends KeyManagerBase<PublicKeySign, EcdsaPrivateKey, EcdsaKeyFormat>
    implements PrivateKeyManager<PublicKeySign> {
  public EcdsaSignKeyManager() {
    super(PublicKeySign.class, EcdsaPrivateKey.class, EcdsaKeyFormat.class, TYPE_URL);
  }

  /** Type url that this manager supports */
  public static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";

  /** Current version of this key manager. Keys with greater version are not supported. */
  private static final int VERSION = 0;

  @Override
  public PublicKeySign getPrimitiveFromKey(EcdsaPrivateKey keyProto)
      throws GeneralSecurityException {
    ECPrivateKey privateKey =
        EllipticCurves.getEcPrivateKey(
            SigUtil.toCurveType(keyProto.getPublicKey().getParams().getCurve()),
            keyProto.getKeyValue().toByteArray());
    return new EcdsaSignJce(
        privateKey,
        SigUtil.toHashType(keyProto.getPublicKey().getParams().getHashType()),
        SigUtil.toEcdsaEncoding(keyProto.getPublicKey().getParams().getEncoding()));
  }

  @Override
  public EcdsaPrivateKey newKeyFromFormat(EcdsaKeyFormat format)
      throws GeneralSecurityException {
    EcdsaParams ecdsaParams = format.getParams();
    KeyPair keyPair = EllipticCurves.generateKeyPair(SigUtil.toCurveType(ecdsaParams.getCurve()));
    ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();
    ECPoint w = pubKey.getW();

    // Creates EcdsaPublicKey.
    EcdsaPublicKey ecdsaPubKey =
        EcdsaPublicKey.newBuilder()
            .setVersion(VERSION)
            .setParams(ecdsaParams)
            .setX(ByteString.copyFrom(w.getAffineX().toByteArray()))
            .setY(ByteString.copyFrom(w.getAffineY().toByteArray()))
            .build();

    // Creates EcdsaPrivateKey.
    return EcdsaPrivateKey.newBuilder()
        .setVersion(VERSION)
        .setPublicKey(ecdsaPubKey)
        .setKeyValue(ByteString.copyFrom(privKey.getS().toByteArray()))
        .build();
  }

  @Override
  public KeyData getPublicKeyData(ByteString serializedKey) throws GeneralSecurityException {
    try {
      EcdsaPrivateKey privKeyProto = EcdsaPrivateKey.parseFrom(serializedKey);
      return KeyData.newBuilder()
          .setTypeUrl(EcdsaVerifyKeyManager.TYPE_URL)
          .setValue(privKeyProto.getPublicKey().toByteString())
          .setKeyMaterialType(KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC)
          .build();
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized EcdsaPrivateKey proto", e);
    }
  }

  @Override
  protected KeyMaterialType keyMaterialType() {
    return KeyMaterialType.ASYMMETRIC_PRIVATE;
  }

  @Override
  protected EcdsaPrivateKey parseKeyProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return EcdsaPrivateKey.parseFrom(byteString);
  }

  @Override
  protected EcdsaKeyFormat parseKeyFormatProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return EcdsaKeyFormat.parseFrom(byteString);
  }

  @Override
  public int getVersion() {
    return VERSION;
  }

  @Override
  protected void validateKey(EcdsaPrivateKey privKey) throws GeneralSecurityException {
    Validators.validateVersion(privKey.getVersion(), VERSION);
    SigUtil.validateEcdsaParams(privKey.getPublicKey().getParams());
  }

  @Override
  protected void validateKeyFormat(EcdsaKeyFormat format) throws GeneralSecurityException {
    SigUtil.validateEcdsaParams(format.getParams());
  }
}
