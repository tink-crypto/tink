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

package com.google.cloud.crypto.tink.hybrid;

import com.google.cloud.crypto.tink.EciesAeadHkdfProto.EciesAeadHkdfPublicKey;
import com.google.cloud.crypto.tink.EciesAeadHkdfProto.EciesHkdfKemParams;
import com.google.cloud.crypto.tink.HybridEncrypt;
import com.google.cloud.crypto.tink.KeyManager;
import com.google.cloud.crypto.tink.TinkProto.KeyFormat;
import com.google.cloud.crypto.tink.Util;
import com.google.cloud.crypto.tink.subtle.SubtleUtil;
import com.google.protobuf.Any;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;

class EciesAeadHkdfPublicKeyManager implements KeyManager<HybridEncrypt> {
  private static final int VERSION = 0;

  private static final String ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE =
      "type.googleapis.com/google.cloud.crypto.tink.EciesAeadHkdfPublicKey";

  @Override
  public HybridEncrypt getPrimitive(Any proto) throws GeneralSecurityException {
    try {
      EciesAeadHkdfPublicKey recipientKeyProto = proto.unpack(EciesAeadHkdfPublicKey.class);
      validate(recipientKeyProto);
      EciesHkdfKemParams kemParams = recipientKeyProto.getParams().getKemParams();
      ECPublicKey recipientPublicKey = Util.getEcPublicKey(kemParams.getCurveType(),
          recipientKeyProto.getX().toByteArray(), recipientKeyProto.getY().toByteArray());
      return new EciesAeadHkdfHybridEncrypt(recipientPublicKey,
          kemParams.getHkdfSalt().toByteArray(),
          Util.hashToHmacAlgorithmName(kemParams.getHkdfHashType()),
          recipientKeyProto.getParams().getDemParams().getAeadDem(),
          recipientKeyProto.getParams().getEcPointFormat());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Invalid EciesAeadHkdfPublicKey.");
    }
  }

  @Override
  public Any newKey(KeyFormat keyFormat) throws GeneralSecurityException {
    throw new GeneralSecurityException("Not implemented.");
  }

  @Override
  public boolean doesSupport(String typeUrl) {
    return ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE.equals(typeUrl);
  }

  private void validate(EciesAeadHkdfPublicKey key) throws GeneralSecurityException {
    // TODO(przydatek): add more checks.
    SubtleUtil.validateVersion(key.getVersion(), VERSION);
  }

}
