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
import com.google.crypto.tink.KeyManagerBase;
import com.google.crypto.tink.PrivateKeyManager;
import com.google.crypto.tink.proto.EciesAeadHkdfKeyFormat;
import com.google.crypto.tink.proto.EciesAeadHkdfParams;
import com.google.crypto.tink.proto.EciesAeadHkdfPrivateKey;
import com.google.crypto.tink.proto.EciesAeadHkdfPublicKey;
import com.google.crypto.tink.proto.EciesHkdfKemParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.EciesAeadHkdfDemHelper;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridDecrypt;
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
 * This key manager generates new {@code EciesAeadHkdfPrivateKey} keys and produces new instances of
 * {@code EciesAeadHkdfHybridDecrypt}.
 */
class EciesAeadHkdfPrivateKeyManager
    extends KeyManagerBase<HybridDecrypt, EciesAeadHkdfPrivateKey, EciesAeadHkdfKeyFormat>
    implements PrivateKeyManager<HybridDecrypt> {
  public EciesAeadHkdfPrivateKeyManager() {
    super(
        HybridDecrypt.class, EciesAeadHkdfPrivateKey.class, EciesAeadHkdfKeyFormat.class, TYPE_URL);
  }

  private static final int VERSION = 0;

  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";

  @Override
  public HybridDecrypt getPrimitiveFromKey(EciesAeadHkdfPrivateKey recipientKeyProto)
      throws GeneralSecurityException {
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

  @Override
  public EciesAeadHkdfPrivateKey newKeyFromFormat(EciesAeadHkdfKeyFormat eciesKeyFormat)
      throws GeneralSecurityException {
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
  protected KeyMaterialType keyMaterialType() {
    return KeyMaterialType.ASYMMETRIC_PRIVATE;
  }

  @Override
  protected EciesAeadHkdfPrivateKey parseKeyProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return EciesAeadHkdfPrivateKey.parseFrom(byteString);
  }

  @Override
  protected EciesAeadHkdfKeyFormat parseKeyFormatProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return EciesAeadHkdfKeyFormat.parseFrom(byteString);
  }

  @Override
  public int getVersion() {
    return VERSION;
  }

  @Override
  protected void validateKey(EciesAeadHkdfPrivateKey keyProto) throws GeneralSecurityException {
    // TODO(b/74249437): add more checks.
    Validators.validateVersion(keyProto.getVersion(), VERSION);
    HybridUtil.validate(keyProto.getPublicKey().getParams());
  }

  @Override
  protected void validateKeyFormat(EciesAeadHkdfKeyFormat eciesKeyFormat)
      throws GeneralSecurityException {
    HybridUtil.validate(eciesKeyFormat.getParams());
  }
}
