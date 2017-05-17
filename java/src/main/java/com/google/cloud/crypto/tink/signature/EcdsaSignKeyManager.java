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

import com.google.cloud.crypto.tink.EcdsaProto.EcdsaKeyFormat;
import com.google.cloud.crypto.tink.EcdsaProto.EcdsaParams;
import com.google.cloud.crypto.tink.EcdsaProto.EcdsaPrivateKey;
import com.google.cloud.crypto.tink.EcdsaProto.EcdsaPublicKey;
import com.google.cloud.crypto.tink.KeyManager;
import com.google.cloud.crypto.tink.PublicKeySign;
import com.google.cloud.crypto.tink.TinkProto.KeyData;
import com.google.cloud.crypto.tink.Util;
import com.google.cloud.crypto.tink.subtle.EcdsaSignJce;
import com.google.cloud.crypto.tink.subtle.SubtleUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

/**
 * This key manager generates new {@code EcdsaPrivateKey} keys and produces new instances
 * of {@code EcdsaSignJce}.
 */
public final class EcdsaSignKeyManager implements KeyManager<PublicKeySign> {
  EcdsaSignKeyManager() {}

  /**
   * Type url that this manager supports
   */
  public static final String TYPE_URL =
      "type.googleapis.com/google.cloud.crypto.tink.EcdsaPrivateKey";

  /**
   * Current version of this key manager.
   * Keys with greater version are not supported.
   */
  private static final int VERSION = 0;

  /**
   * @param serializedKey  serialized {@code EcdsaPrivateKey} proto
   */
  @Override
  public PublicKeySign getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      EcdsaPrivateKey privKeyProto = EcdsaPrivateKey.parseFrom(serializedKey);
      return getPrimitive(privKeyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized EcdsaPrivateKey proto", e);
    }
  }

  /**
   * @param key  {@code EcdsaPrivateKey} proto
   */
  @Override
  public PublicKeySign getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof EcdsaPrivateKey)) {
      throw new GeneralSecurityException("expected EcdsaPrivateKey proto");
    }
    EcdsaPrivateKey keyProto = (EcdsaPrivateKey) key;
    validateKey(keyProto);
    ECPrivateKey privateKey = Util.getEcPrivateKey(
        keyProto.getPublicKey().getParams().getCurve(),
        keyProto.getKeyValue().toByteArray());
    return new EcdsaSignJce(privateKey,
        SigUtil.hashToEcdsaAlgorithmName(keyProto.getPublicKey().getParams().getHashType()));
  }

  /**
   * @param serializedKeyFormat  serialized {@code EcdsaKeyFormat} proto
   * @return new {@code EcdsaPrivateKey} proto
   */
  @Override
  public MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    try {
      EcdsaKeyFormat ecdsaKeyFormat = EcdsaKeyFormat.parseFrom(serializedKeyFormat);
      return newKey(ecdsaKeyFormat);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected EcdsaKeyFormat proto", e);
    }
  }

  /**
   * @param keyFormat  {@code EcdsaKeyFormat} proto
   * @return new {@code EcdsaPrivateKey} proto
   */
  @Override
  public MessageLite newKey(MessageLite keyFormat) throws GeneralSecurityException {
    if (!(keyFormat instanceof EcdsaKeyFormat)) {
      throw new GeneralSecurityException("expected EcdsaKeyFormat proto");
    }
    EcdsaKeyFormat format = (EcdsaKeyFormat) keyFormat;
    EcdsaParams ecdsaParams = format.getParams();
    SigUtil.validateEcdsaParams(ecdsaParams);
    KeyPair keyPair = Util.generateKeyPair(ecdsaParams.getCurve());
    ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();
    ECPoint w = pubKey.getW();

    // Creates EcdsaPublicKey.
    EcdsaPublicKey ecdsaPubKey = EcdsaPublicKey.newBuilder()
        .setVersion(VERSION)
        .setParams(ecdsaParams)
        .setX(ByteString.copyFrom(w.getAffineX().toByteArray()))
        .setY(ByteString.copyFrom(w.getAffineY().toByteArray()))
        .build();

    //Creates EcdsaPrivateKey.
    return EcdsaPrivateKey.newBuilder()
        .setVersion(VERSION)
        .setPublicKey(ecdsaPubKey)
        .setKeyValue(ByteString.copyFrom(privKey.getS().toByteArray()))
        .build();
  }

  /**
   * @param serializedKeyFormat  serialized {@code EcdsaKeyFormat} proto
   * @return {@code KeyData} with a new {@code EcdsaPrivateKey} proto
   */
  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    EcdsaPrivateKey key = (EcdsaPrivateKey) newKey(serializedKeyFormat);
    return KeyData.newBuilder()
        .setTypeUrl(TYPE_URL)
        .setValue(key.toByteString())
        .setKeyMaterialType(KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE)
        .build();
  }

  @Override
  public boolean doesSupport(String typeUrl) {
    return TYPE_URL.equals(typeUrl);
  }

  private void validateKey(EcdsaPrivateKey privKey) throws GeneralSecurityException {
    SubtleUtil.validateVersion(privKey.getVersion(), VERSION);
    SigUtil.validateEcdsaParams(privKey.getPublicKey().getParams());
  }
}
