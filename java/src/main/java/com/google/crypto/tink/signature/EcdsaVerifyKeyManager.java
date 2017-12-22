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
import com.google.crypto.tink.Util;
import com.google.crypto.tink.proto.EcdsaKeyFormat;
import com.google.crypto.tink.proto.EcdsaParams;
import com.google.crypto.tink.proto.EcdsaPublicKey;
import com.google.crypto.tink.proto.EcdsaSignatureEncoding;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.EcdsaVerifyJce;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;
import org.json.JSONException;
import org.json.JSONObject;

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
    return new EcdsaVerifyJce(publicKey, SigUtil.toEcdsaAlgo(keyProto.getParams().getHashType()));
  }

  /**
   * Not supported, please use {@link EcdsaSignKeyManager}.
   */
  @Override
  public MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    throw new GeneralSecurityException(
        "Not supported, please use the manager of the corresponding signing key.");
  }

  /**
   * Not supported, please use {@link EcdsaSignKeyManager}.
   */
  @Override
  public MessageLite newKey(MessageLite keyFormat) throws GeneralSecurityException {
    throw new GeneralSecurityException(
        "Not supported, please use the manager of the corresponding signing key.");
  }

  /**
   * Not supported, please use {@link EcdsaSignKeyManager}.
   */
  @Override
  public KeyData newKeyData(ByteString serialized) throws GeneralSecurityException {
    throw new GeneralSecurityException(
        "Not supported, please use the manager of the corresponding signing key.");
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

  /**
   * @param jsonKey JSON formatted {@code EcdsaPublicKey}-proto
   * @return {@code EcdsaPublicKey}-proto
   */
  @Override
  public MessageLite jsonToKey(final byte[] jsonKey) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKey, Util.UTF_8));
      validateKey(json);
      return EcdsaPublicKey.newBuilder()
          .setVersion(json.getInt("version"))
          .setParams(paramsFromJson(json.getJSONObject("params")))
          .setX(ByteString.copyFrom(Base64.decode(json.getString("x"))))
          .setY(ByteString.copyFrom(Base64.decode(json.getString("y"))))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * @param jsonKeyFormat JSON formatted {@code EcdsaKeyFromat}-proto
   * @return {@code EcdsaKeyFormat}-proto
   */
  @Override
  public MessageLite jsonToKeyFormat(final byte[] jsonKeyFormat) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKeyFormat, Util.UTF_8));
      validateKeyFormat(json);
      return EcdsaKeyFormat.newBuilder()
          .setParams(paramsFromJson(json.getJSONObject("params")))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * Returns a JSON-formatted serialization of the given {@code serializedKey},
   * which must be a {@code EcdsaPublicKey}-proto.
   * @throws GeneralSecurityException if the key in {@code serializedKey} is not supported
   */
  @Override
  public byte[] keyToJson(ByteString serializedKey) throws GeneralSecurityException {
    EcdsaPublicKey key;
    try {
      key = EcdsaPublicKey.parseFrom(serializedKey);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized EcdsaPublicKey proto", e);
    }
    validate(key);
    try {
      return new JSONObject()
          .put("version", key.getVersion())
          .put("params", toJson(key.getParams()))
          .put("x", Base64.encode(key.getX().toByteArray()))
          .put("y", Base64.encode(key.getY().toByteArray()))
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
    EcdsaKeyFormat format;
    try {
      format = EcdsaKeyFormat.parseFrom(serializedKeyFormat);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized EcdsaKeyFormat proto", e);
    }
    validate(format);
    try {
      return new JSONObject()
          .put("params", toJson(format.getParams()))
          .toString(4).getBytes(Util.UTF_8);
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * Returns a {@code EcdsaSignatureEncoding}-enum corresponding to the given string representation.
   */
  private EcdsaSignatureEncoding getEcdsaSignatureEncoding(String encoding)
      throws GeneralSecurityException {
    String uEncoding = encoding.toUpperCase();
    if (uEncoding.equals("IEEE_P1363")) {
      return EcdsaSignatureEncoding.IEEE_P1363;
    } else if (uEncoding.equals("DER")) {
      return EcdsaSignatureEncoding.DER;
    }
    throw new GeneralSecurityException("unknown ECDSA signature encoding: " + encoding);
  }

  private JSONObject toJson(EcdsaParams params) throws JSONException {
    return new JSONObject()
        .put("hashType", params.getHashType().toString())
        .put("curve", params.getCurve().toString())
        .put("encoding", params.getEncoding().toString());
  }

  private EcdsaParams paramsFromJson(JSONObject json) throws
      JSONException, GeneralSecurityException {
    if (json.length() != 3 || !json.has("hashType") || !json.has("curve")
        || !json.has("encoding")) {
      throw new JSONException("Invalid params.");
    }
    return EcdsaParams.newBuilder()
        .setHashType(Util.getHashType(json.getString("hashType")))
        .setCurve(Util.getEllipticCurveType(json.getString("curve")))
        .setEncoding(getEcdsaSignatureEncoding(json.getString("encoding")))
        .build();
  }

  private void validateKey(JSONObject json) throws JSONException {
    if (json.length() != 4 || !json.has("version") || !json.has("params")
        || !json.has("x") || !json.has("y")) {
      throw new JSONException("Invalid key.");
    }
  }

  private void validateKeyFormat(JSONObject json) throws JSONException {
    if (json.length() != 1 || !json.has("params")) {
      throw new JSONException("Invalid key format.");
    }
  }

  private void validate(EcdsaPublicKey pubKey) throws GeneralSecurityException {
    Validators.validateVersion(pubKey.getVersion(), VERSION);
    SigUtil.validateEcdsaParams(pubKey.getParams());
  }

  private void validate(EcdsaKeyFormat format) throws GeneralSecurityException {
    SigUtil.validateEcdsaParams(format.getParams());
  }

}
