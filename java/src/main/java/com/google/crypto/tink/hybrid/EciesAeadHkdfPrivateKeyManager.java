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
import com.google.crypto.tink.PrivateKeyTypeManager;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.EciesAeadHkdfKeyFormat;
import com.google.crypto.tink.proto.EciesAeadHkdfParams;
import com.google.crypto.tink.proto.EciesAeadHkdfPrivateKey;
import com.google.crypto.tink.proto.EciesAeadHkdfPublicKey;
import com.google.crypto.tink.proto.EciesHkdfKemParams;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.EciesAeadHkdfDemHelper;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridDecrypt;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
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
public class EciesAeadHkdfPrivateKeyManager
    extends PrivateKeyTypeManager<EciesAeadHkdfPrivateKey, EciesAeadHkdfPublicKey> {
  EciesAeadHkdfPrivateKeyManager() {
    super(
        EciesAeadHkdfPrivateKey.class,
        EciesAeadHkdfPublicKey.class,
        new PrimitiveFactory<HybridDecrypt, EciesAeadHkdfPrivateKey>(HybridDecrypt.class) {
          @Override
          public HybridDecrypt getPrimitive(EciesAeadHkdfPrivateKey recipientKeyProto)
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
        });
  }

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public EciesAeadHkdfPublicKey getPublicKey(EciesAeadHkdfPrivateKey key)
      throws GeneralSecurityException {
    return key.getPublicKey();
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.ASYMMETRIC_PRIVATE;
  }

  @Override
  public EciesAeadHkdfPrivateKey parseKey(ByteString byteString)
      throws InvalidProtocolBufferException {
    return EciesAeadHkdfPrivateKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public void validateKey(EciesAeadHkdfPrivateKey keyProto) throws GeneralSecurityException {
    if (keyProto.getKeyValue().isEmpty()) {
      throw new GeneralSecurityException("invalid ECIES private key");
    }
    Validators.validateVersion(keyProto.getVersion(), getVersion());
    HybridUtil.validate(keyProto.getPublicKey().getParams());
  }

  @Override
  public KeyFactory<EciesAeadHkdfKeyFormat, EciesAeadHkdfPrivateKey> keyFactory() {
    return new KeyFactory<EciesAeadHkdfKeyFormat, EciesAeadHkdfPrivateKey>(
        EciesAeadHkdfKeyFormat.class) {
      @Override
      public void validateKeyFormat(EciesAeadHkdfKeyFormat eciesKeyFormat)
          throws GeneralSecurityException {
        HybridUtil.validate(eciesKeyFormat.getParams());
      }

      @Override
      public EciesAeadHkdfKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return EciesAeadHkdfKeyFormat.parseFrom(
            byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public EciesAeadHkdfPrivateKey createKey(EciesAeadHkdfKeyFormat eciesKeyFormat)
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
                .setVersion(getVersion())
                .setParams(eciesKeyFormat.getParams())
                .setX(ByteString.copyFrom(w.getAffineX().toByteArray()))
                .setY(ByteString.copyFrom(w.getAffineY().toByteArray()))
                .build();

        // Creates EciesAeadHkdfPrivateKey.
        return EciesAeadHkdfPrivateKey.newBuilder()
            .setVersion(getVersion())
            .setPublicKey(eciesPublicKey)
            .setKeyValue(ByteString.copyFrom(privKey.getS().toByteArray()))
            .build();
      }
    };
  }

  /**
   * Registers the {@link EciesAeadHkdfPrivateKeyManager} and the {@link
   * EciesAeadHkdfPublicKeyManager} with the registry, so that the the EciesAeadHkdfKeys can be used
   * with Tink.
   */
  public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerAsymmetricKeyManagers(
        new EciesAeadHkdfPrivateKeyManager(), new EciesAeadHkdfPublicKeyManager(), newKeyAllowed);
  }
}
