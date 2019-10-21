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

import com.google.crypto.tink.PrivateKeyTypeManager;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.EcdsaKeyFormat;
import com.google.crypto.tink.proto.EcdsaParams;
import com.google.crypto.tink.proto.EcdsaPrivateKey;
import com.google.crypto.tink.proto.EcdsaPublicKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.EcdsaSignJce;
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
 * This key manager generates new {@code EcdsaPrivateKey} keys and produces new instances of {@code
 * EcdsaSignJce}.
 */
public class EcdsaSignKeyManager extends PrivateKeyTypeManager<EcdsaPrivateKey, EcdsaPublicKey> {
  EcdsaSignKeyManager() {
    super(
        EcdsaPrivateKey.class,
        EcdsaPublicKey.class,
        new PrimitiveFactory<PublicKeySign, EcdsaPrivateKey>(PublicKeySign.class) {
          @Override
          public PublicKeySign getPrimitive(EcdsaPrivateKey key) throws GeneralSecurityException {
            ECPrivateKey privateKey =
                EllipticCurves.getEcPrivateKey(
                    SigUtil.toCurveType(key.getPublicKey().getParams().getCurve()),
                    key.getKeyValue().toByteArray());
            return new EcdsaSignJce(
                privateKey,
                SigUtil.toHashType(key.getPublicKey().getParams().getHashType()),
                SigUtil.toEcdsaEncoding(key.getPublicKey().getParams().getEncoding()));
          }
        });
  }

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public EcdsaPublicKey getPublicKey(EcdsaPrivateKey key) throws GeneralSecurityException {
    return key.getPublicKey();
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.ASYMMETRIC_PRIVATE;
  }

  @Override
  public EcdsaPrivateKey parseKey(ByteString byteString)
      throws InvalidProtocolBufferException {
    return EcdsaPrivateKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public void validateKey(EcdsaPrivateKey privKey) throws GeneralSecurityException {
    Validators.validateVersion(privKey.getVersion(), getVersion());
    SigUtil.validateEcdsaParams(privKey.getPublicKey().getParams());
  }

  @Override
  public KeyFactory<EcdsaKeyFormat, EcdsaPrivateKey> keyFactory() {
    return new KeyFactory<EcdsaKeyFormat, EcdsaPrivateKey>(EcdsaKeyFormat.class) {
      @Override
      public void validateKeyFormat(EcdsaKeyFormat format) throws GeneralSecurityException {
        SigUtil.validateEcdsaParams(format.getParams());
      }

      @Override
      public EcdsaKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return EcdsaKeyFormat.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public EcdsaPrivateKey createKey(EcdsaKeyFormat format) throws GeneralSecurityException {
        EcdsaParams ecdsaParams = format.getParams();
        KeyPair keyPair =
            EllipticCurves.generateKeyPair(SigUtil.toCurveType(ecdsaParams.getCurve()));
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();
        ECPoint w = pubKey.getW();

        // Creates EcdsaPublicKey.
        EcdsaPublicKey ecdsaPubKey =
            EcdsaPublicKey.newBuilder()
                .setVersion(getVersion())
                .setParams(ecdsaParams)
                .setX(ByteString.copyFrom(w.getAffineX().toByteArray()))
                .setY(ByteString.copyFrom(w.getAffineY().toByteArray()))
                .build();

        // Creates EcdsaPrivateKey.
        return EcdsaPrivateKey.newBuilder()
            .setVersion(getVersion())
            .setPublicKey(ecdsaPubKey)
            .setKeyValue(ByteString.copyFrom(privKey.getS().toByteArray()))
            .build();
      }
    };
  }

  /**
   * Registers the {@link EcdsaSignKeyManager} and the {@link EcdsaVerifyKeyManager} with the
   * registry, so that the the Ecdsa-Keys can be used with Tink.
   */
  public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerAsymmetricKeyManagers(
        new EcdsaSignKeyManager(), new EcdsaVerifyKeyManager(), newKeyAllowed);
  }
}
