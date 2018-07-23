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

import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.proto.EcdsaPublicKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.EcdsaVerifyJce;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;

/**
 * This key manager produces new instances of {@code EcdsaVerifyJce}. It doesn't support key
 * generation.
 */
class EcdsaVerifyKeyManager implements KeyManager<PublicKeyVerify> {
  public static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.EcdsaPublicKey";
  /** Current version of this key manager. Keys with greater version are not supported. */
  private static final int VERSION = 0;

  /** @param serializedKey serialized {@code EcdsaPublicKey} proto */
  @Override
  public PublicKeyVerify getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      EcdsaPublicKey pubKey = EcdsaPublicKey.parseFrom(serializedKey);
      return getPrimitive(pubKey);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized EcdsaPublicKey proto", e);
    }
  }

  /** @param key {@code EcdsaPublicKey} proto */
  @Override
  public PublicKeyVerify getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof EcdsaPublicKey)) {
      throw new GeneralSecurityException("expected EcdsaPublicKey proto");
    }
    EcdsaPublicKey keyProto = (EcdsaPublicKey) key;
    validate(keyProto);
    ECPublicKey publicKey =
        EllipticCurves.getEcPublicKey(
            SigUtil.toCurveType(keyProto.getParams().getCurve()),
            keyProto.getX().toByteArray(),
            keyProto.getY().toByteArray());
    return new EcdsaVerifyJce(
        publicKey,
        SigUtil.toEcdsaAlgo(keyProto.getParams().getHashType()),
        SigUtil.toEcdsaEncoding(keyProto.getParams().getEncoding()));
  }

  /**
   * @param serializedKeyFormat serialized {@code EcdsaKeyFormat} proto
   * @return new {@code EcdsaPublicKey} proto
   */
  @Override
  public MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    throw new GeneralSecurityException("Not implemented");
  }

  /**
   * @param keyFormat {@code EcdsaKeyFormat} proto
   * @return new {@code EcdsaPublicKey} proto
   */
  @Override
  public MessageLite newKey(MessageLite keyFormat) throws GeneralSecurityException {
    throw new GeneralSecurityException("Not implemented");
  }

  /**
   * @param serializedKeyFormat serialized {@code EcdsaKeyFormat} proto
   * @return {@code KeyData} with a new {@code EcdsaPublicKey} proto
   */
  @Override
  public KeyData newKeyData(ByteString serialized) throws GeneralSecurityException {
    throw new GeneralSecurityException("Not implemented");
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

  private void validate(EcdsaPublicKey pubKey) throws GeneralSecurityException {
    Validators.validateVersion(pubKey.getVersion(), VERSION);
    SigUtil.validateEcdsaParams(pubKey.getParams());
  }
}
