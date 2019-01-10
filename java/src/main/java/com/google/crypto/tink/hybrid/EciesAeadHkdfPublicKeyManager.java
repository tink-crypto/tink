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

import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeyManagerBase;
import com.google.crypto.tink.proto.EciesAeadHkdfParams;
import com.google.crypto.tink.proto.EciesAeadHkdfPublicKey;
import com.google.crypto.tink.proto.EciesHkdfKemParams;
import com.google.crypto.tink.proto.Empty;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.EciesAeadHkdfDemHelper;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridEncrypt;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;

/**
 * This key manager produces new instances of {@code EciesAeadHkdfHybridEncrypt}. It doesn't support
 * key generation.
 */
class EciesAeadHkdfPublicKeyManager
    extends KeyManagerBase<HybridEncrypt, EciesAeadHkdfPublicKey, Empty> {
  public EciesAeadHkdfPublicKeyManager() {
    super(HybridEncrypt.class, EciesAeadHkdfPublicKey.class, Empty.class, TYPE_URL);
  }

  private static final int VERSION = 0;

  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";

  @Override
  protected HybridEncrypt getPrimitiveFromKey(EciesAeadHkdfPublicKey recipientKeyProto)
      throws GeneralSecurityException {
    EciesAeadHkdfParams eciesParams = recipientKeyProto.getParams();
    EciesHkdfKemParams kemParams = eciesParams.getKemParams();
    ECPublicKey recipientPublicKey =
        EllipticCurves.getEcPublicKey(
            HybridUtil.toCurveType(kemParams.getCurveType()),
            recipientKeyProto.getX().toByteArray(),
            recipientKeyProto.getY().toByteArray());
    EciesAeadHkdfDemHelper demHelper =
        new RegistryEciesAeadHkdfDemHelper(eciesParams.getDemParams().getAeadDem());
    return new EciesAeadHkdfHybridEncrypt(
        recipientPublicKey,
        kemParams.getHkdfSalt().toByteArray(),
        HybridUtil.toHmacAlgo(kemParams.getHkdfHashType()),
        HybridUtil.toPointFormatType(eciesParams.getEcPointFormat()),
        demHelper);
  }

  @Override
  public EciesAeadHkdfPublicKey newKeyFromFormat(Empty format) throws GeneralSecurityException {
    throw new GeneralSecurityException("Not implemented.");
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
  protected EciesAeadHkdfPublicKey parseKeyProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return EciesAeadHkdfPublicKey.parseFrom(byteString);
  }

  @Override
  protected Empty parseKeyFormatProto(ByteString byteString) throws InvalidProtocolBufferException {
    return Empty.parseFrom(byteString);
  }

  @Override
  protected void validateKey(EciesAeadHkdfPublicKey key) throws GeneralSecurityException {
    // TODO(b/74251423): add more checks.
    Validators.validateVersion(key.getVersion(), VERSION);
    HybridUtil.validate(key.getParams());
  }

  @Override
  protected void validateKeyFormat(Empty unused) throws GeneralSecurityException {}
}
