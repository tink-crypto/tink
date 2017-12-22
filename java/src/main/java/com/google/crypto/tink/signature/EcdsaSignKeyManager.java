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

import com.google.crypto.tink.PrivateKeyManager;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.Util;
import com.google.crypto.tink.proto.EcdsaKeyFormat;
import com.google.crypto.tink.proto.EcdsaParams;
import com.google.crypto.tink.proto.EcdsaPrivateKey;
import com.google.crypto.tink.proto.EcdsaPublicKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.EcdsaSignJce;
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
import org.json.JSONException;
import org.json.JSONObject;

/**
 * This key manager generates new {@code EcdsaPrivateKey} keys and produces new instances of {@code
 * EcdsaSignJce}.
 */
class EcdsaSignKeyManager implements PrivateKeyManager<PublicKeySign> {
  /** Type url that this manager supports */
  public static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";

  /** Current version of this key manager. Keys with greater version are not supported. */
  private static final int VERSION = 0;

  /** @param serializedKey serialized {@code EcdsaPrivateKey} proto */
  @Override
  public PublicKeySign getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      EcdsaPrivateKey privKeyProto = EcdsaPrivateKey.parseFrom(serializedKey);
      return getPrimitive(privKeyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized EcdsaPrivateKey proto", e);
    }
  }

  /** @param key {@code EcdsaPrivateKey} proto */
  @Override
  public PublicKeySign getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof EcdsaPrivateKey)) {
      throw new GeneralSecurityException("expected EcdsaPrivateKey proto");
    }
    EcdsaPrivateKey keyProto = (EcdsaPrivateKey) key;
    validate(keyProto);
    ECPrivateKey privateKey =
        EllipticCurves.getEcPrivateKey(
            SigUtil.toCurveType(keyProto.getPublicKey().getParams().getCurve()),
            keyProto.getKeyValue().toByteArray());
    return new EcdsaSignJce(
        privateKey, SigUtil.toEcdsaAlgo(keyProto.getPublicKey().getParams().getHashType()));
  }

  /**
   * @param serializedKeyFormat serialized {@code EcdsaKeyFormat} proto
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
   * @param keyFormat {@code EcdsaKeyFormat} proto
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

  /**
   * @param serializedKeyFormat serialized {@code EcdsaKeyFormat} proto
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
  public String getKeyType() {
    return TYPE_URL;
  }

  @Override
  public boolean doesSupport(String typeUrl) {
    return TYPE_URL.equals(typeUrl);
  }

  @Override
  public int getVersion() {
    return VERSION;
  }

  /**
   * @param jsonKey JSON formatted {@code EcdsaPrivateKey}-proto
   * @return {@code EcdsaPrivateKey}-proto
   */
  @Override
  public MessageLite jsonToKey(final byte[] jsonKey) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKey, Util.UTF_8));
      validateKey(json);
      EcdsaVerifyKeyManager publicKeyManager = new EcdsaVerifyKeyManager();
      return EcdsaPrivateKey.newBuilder()
          .setVersion(json.getInt("version"))
          .setPublicKey((EcdsaPublicKey) publicKeyManager.jsonToKey(
              json.getJSONObject("publicKey").toString(4).getBytes(Util.UTF_8)))
          .setKeyValue(ByteString.copyFrom(Base64.decode(json.getString("keyValue"))))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * @param jsonKeyFormat JSON formatted {@code EcdsaPrivateKeyFromat}-proto
   * @return {@code EcdsaKeyFormat}-proto
   */
  @Override
  public MessageLite jsonToKeyFormat(final byte[] jsonKeyFormat) throws GeneralSecurityException {
    return new EcdsaVerifyKeyManager().jsonToKeyFormat(jsonKeyFormat);
  }

  /**
   * Returns a JSON-formatted serialization of the given {@code serializedKey},
   * which must be a {@code EcdsaPrivateKey}-proto.
   * @throws GeneralSecurityException if the key in {@code serializedKey} is not supported
   */
  @Override
  public byte[] keyToJson(ByteString serializedKey) throws GeneralSecurityException {
    EcdsaPrivateKey key;
    try {
      key = EcdsaPrivateKey.parseFrom(serializedKey);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized EcdsaPrivateKey proto", e);
    }
    validate(key);
    EcdsaVerifyKeyManager publicKeyManager = new EcdsaVerifyKeyManager();
    try {
      return new JSONObject()
          .put("version", key.getVersion())
          .put("publicKey", new JSONObject(new String(
              publicKeyManager.keyToJson(key.getPublicKey().toByteString()), Util.UTF_8)))
          .put("keyValue", Base64.encode(key.getKeyValue().toByteArray()))
          .toString(4).getBytes(Util.UTF_8);
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * Returns a JSON-formatted serialization of the given {@code serializedKeyFormat}
   * which must be a {@code EcdsaKeyFormat}-proto.
   * @throws GeneralSecurityException if the format in {@code serializedKeyFromat} is not supported
   */
  @Override
  public byte[] keyFormatToJson(ByteString serializedKeyFormat) throws GeneralSecurityException {
    return new EcdsaVerifyKeyManager().keyFormatToJson(serializedKeyFormat);
  }

  private void validateKey(JSONObject json) throws JSONException {
    if (json.length() != 3 || !json.has("version") || !json.has("publicKey")
        || !json.has("keyValue")) {
      throw new JSONException("Invalid key.");
    }
  }

  private void validate(EcdsaPrivateKey privKey) throws GeneralSecurityException {
    Validators.validateVersion(privKey.getVersion(), VERSION);
    SigUtil.validateEcdsaParams(privKey.getPublicKey().getParams());
  }
}
