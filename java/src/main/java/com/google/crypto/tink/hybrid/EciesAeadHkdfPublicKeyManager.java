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
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.proto.EciesAeadHkdfParams;
import com.google.crypto.tink.proto.EciesAeadHkdfPublicKey;
import com.google.crypto.tink.proto.EciesHkdfKemParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.EcUtil;
import com.google.crypto.tink.subtle.EciesAeadHkdfDemHelper;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridEncrypt;
import com.google.crypto.tink.subtle.SubtleUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;

/**
 * This key manager produces new instances of {@code EciesAeadHkdfHybridEncrypt}.
 * It doesn't support key generation.
 */
public final class EciesAeadHkdfPublicKeyManager implements KeyManager<HybridEncrypt> {
  EciesAeadHkdfPublicKeyManager() {}

  private static final int VERSION = 0;

  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";

  /**
   * @param serializedKey  serialized {@code EciesAeadHkdfPublicKey} proto
   */
  @Override
  public HybridEncrypt getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      EciesAeadHkdfPublicKey recipientKeyProto = EciesAeadHkdfPublicKey.parseFrom(serializedKey);
      return getPrimitive(recipientKeyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized EciesAeadHkdfPublicKey proto", e);
    }
  }

  /**
   * @param recipientKey  {@code EciesAeadHkdfPublicKey} proto
   */
  @Override
  public HybridEncrypt getPrimitive(MessageLite recipientKey) throws GeneralSecurityException {
    if (!(recipientKey instanceof EciesAeadHkdfPublicKey)) {
      throw new GeneralSecurityException("expected EciesAeadHkdfPublicKey proto");
    }
    EciesAeadHkdfPublicKey recipientKeyProto = (EciesAeadHkdfPublicKey) recipientKey;
    validate(recipientKeyProto);
    EciesAeadHkdfParams eciesParams = recipientKeyProto.getParams();
    EciesHkdfKemParams kemParams = eciesParams.getKemParams();
    ECPublicKey recipientPublicKey = EcUtil.getEcPublicKey(kemParams.getCurveType(),
        recipientKeyProto.getX().toByteArray(), recipientKeyProto.getY().toByteArray());
    EciesAeadHkdfDemHelper demHelper = new RegistryEciesAeadHkdfDemHelper(
        eciesParams.getDemParams().getAeadDem());
    return new EciesAeadHkdfHybridEncrypt(recipientPublicKey,
        kemParams.getHkdfSalt().toByteArray(),
        kemParams.getHkdfHashType(),
        eciesParams.getEcPointFormat(),
        demHelper);
  }

  /**
   * @param serializedKeyFormat  serialized {@code EciesAeadHkdfKeyFormat} proto
   * @return new {@code EciesAeadHkdfPublicKey} proto
   */
  @Override
  public MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    throw new GeneralSecurityException("Not implemented.");
  }

  /**
   * @param keyFormat  {@code EciesAeadHkdfKeyFormat} proto
   * @return new {@code EciesAeadHkdfPublicKey} proto
   */
  @Override
  public MessageLite newKey(MessageLite keyFormat) throws GeneralSecurityException {
    throw new GeneralSecurityException("Not implemented.");
  }

  /**
   * @param serializedKeyFormat  serialized {@code EciesAeadHkdfKeyFormat} proto
   * @return {@code KeyData} with a new {@code EciesAeadHkdfPrivateKey} proto
   */
  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    throw new GeneralSecurityException("Not implemented.");
  }

  @Override
  public boolean doesSupport(String typeUrl) {
    return TYPE_URL.equals(typeUrl);
  }

  @Override
  public String getKeyType() {
    return TYPE_URL;
  }

  private void validate(EciesAeadHkdfPublicKey key) throws GeneralSecurityException {
    // TODO(przydatek): add more checks.
    SubtleUtil.validateVersion(key.getVersion(), VERSION);
    HybridUtil.validate(key.getParams());
  }

}
