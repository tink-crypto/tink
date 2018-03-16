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

package com.google.crypto.tink.hybrid;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.PrivateKeyManager;
import com.google.crypto.tink.proto.EciesAeadHkdfKeyFormat;
import com.google.crypto.tink.proto.EciesAeadHkdfParams;
import com.google.crypto.tink.proto.EciesAeadHkdfPrivateKey;
import com.google.crypto.tink.proto.EciesAeadHkdfPublicKey;
import com.google.crypto.tink.proto.EciesHkdfKemParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.EciesAeadHkdfDemHelper;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridDecrypt;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

/**
 * This key manager generates new {@code EciesAeadHkdfPrivateKey} keys and produces new instances of
 * {@code EciesAeadHkdfHybridDecrypt}.
 */
class EciesAeadHkdfPrivateKeyManager implements PrivateKeyManager<HybridDecrypt> {
  private static final int VERSION = 0;

  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";

  /** @param serializedKey serialized {@code EciesAeadHkdfPrivateKey} proto */
  @Override
  public HybridDecrypt getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      EciesAeadHkdfPrivateKey recipientKeyProto = EciesAeadHkdfPrivateKey.parseFrom(serializedKey);
      return getPrimitive(recipientKeyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized EciesAeadHkdfPrivateKey proto", e);
    }
  }

  /** @param recipientKey {@code EciesAeadHkdfPrivateKey} proto */
  @Override
  public HybridDecrypt getPrimitive(MessageLite recipientKey) throws GeneralSecurityException {
    if (!(recipientKey instanceof EciesAeadHkdfPrivateKey)) {
      throw new GeneralSecurityException("expected EciesAeadHkdfPrivateKey proto");
    }
    EciesAeadHkdfPrivateKey recipientKeyProto = (EciesAeadHkdfPrivateKey) recipientKey;
    validate(recipientKeyProto);
    EciesAeadHkdfParams eciesParams = recipientKeyProto.getPublicKey().getParams();
    EciesHkdfKemParams kemParams = eciesParams.getKemParams();

    ECPrivateKey recipientPrivateKey =
        EllipticCurves.getEcPrivateKey(
            HybridUtil.toCurveType(kemParams.getCurveType()),
            recipientKeyProto.getKeyValue().toByteArray());
    EciesAeadHkdfDemHelper demHelper =
        new RegistryEciesAeadHkdfDemHelper(eciesParams.getDemParams().getAeadDem());
    return new EciesAeadHkdfHybridDecrypt(
        recipientPrivateKey,
        kemParams.getHkdfSalt().toByteArray(),
        HybridUtil.toHmacAlgo(kemParams.getHkdfHashType()),
        HybridUtil.toPointFormatType(eciesParams.getEcPointFormat()),
        demHelper);
  }

  /**
   * @param serializedKeyFormat serialized {@code EciesAeadHkdfKeyFormat} proto
   * @return new {@code EciesAeadHkdfPrivateKey} proto
   */
  @Override
  public MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    try {
      EciesAeadHkdfKeyFormat eciesKeyFormat = EciesAeadHkdfKeyFormat.parseFrom(serializedKeyFormat);
      return newKey(eciesKeyFormat);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid EciesAeadHkdf key format", e);
    }
  }

  /**
   * @param keyFormat {@code EciesAeadHkdfKeyFormat} proto
   * @return new {@code EciesAeadHkdfPrivateKey} proto
   */
  @Override
  public MessageLite newKey(MessageLite keyFormat) throws GeneralSecurityException {
    if (!(keyFormat instanceof EciesAeadHkdfKeyFormat)) {
      throw new GeneralSecurityException("expected EciesAeadHkdfKeyFormat proto");
    }
    EciesAeadHkdfKeyFormat eciesKeyFormat = (EciesAeadHkdfKeyFormat) keyFormat;
    HybridUtil.validate(eciesKeyFormat.getParams());
    EciesHkdfKemParams kemParams = eciesKeyFormat.getParams().getKemParams();
    KeyPair keyPair =
        EllipticCurves.generateKeyPair(HybridUtil.toCurveType(kemParams.getCurveType()));
    ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();
    ECPoint w = pubKey.getW();

    // Creates EciesAeadHkdfPublicKey.
    EciesAeadHkdfPublicKey eciesPublicKey =
        EciesAeadHkdfPublicKey.newBuilder()
            .setVersion(VERSION)
            .setParams(eciesKeyFormat.getParams())
            .setX(ByteString.copyFrom(w.getAffineX().toByteArray()))
            .setY(ByteString.copyFrom(w.getAffineY().toByteArray()))
            .build();

    // Creates EciesAeadHkdfPrivateKey.
    return EciesAeadHkdfPrivateKey.newBuilder()
        .setVersion(VERSION)
        .setPublicKey(eciesPublicKey)
        .setKeyValue(ByteString.copyFrom(privKey.getS().toByteArray()))
        .build();
  }

  /**
   * @param serializedKeyFormat serialized {@code EciesAeadHkdfKeyFormat} proto
   * @return {@code KeyData} with a new {@code EciesAeadHkdfPrivateKey} proto
   */
  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    EciesAeadHkdfPrivateKey key = (EciesAeadHkdfPrivateKey) newKey(serializedKeyFormat);
    return KeyData.newBuilder()
        .setTypeUrl(TYPE_URL)
        .setValue(key.toByteString())
        .setKeyMaterialType(KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE)
        .build();
  }

  @Override
  public KeyData getPublicKeyData(ByteString serializedKey) throws GeneralSecurityException {
    try {
      EciesAeadHkdfPrivateKey privKeyProto = EciesAeadHkdfPrivateKey.parseFrom(serializedKey);
      return KeyData.newBuilder()
          .setTypeUrl(EciesAeadHkdfPublicKeyManager.TYPE_URL)
          .setValue(privKeyProto.getPublicKey().toByteString())
          .setKeyMaterialType(KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC)
          .build();
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized EciesAeadHkdfPrivateKey proto", e);
    }
  }

  @Override
  public boolean doesSupport(String typeUrl) {
    return TYPE_URL.equals(typeUrl);
  }

  @Override
  public String getKeyType() {
    return TYPE_URL;
  }

  @Override
  public int getVersion() {
    return VERSION;
  }

  private void validate(EciesAeadHkdfPrivateKey keyProto) throws GeneralSecurityException {
    // TODO(b/74249437): add more checks.
    Validators.validateVersion(keyProto.getVersion(), VERSION);
    HybridUtil.validate(keyProto.getPublicKey().getParams());
  }
}
