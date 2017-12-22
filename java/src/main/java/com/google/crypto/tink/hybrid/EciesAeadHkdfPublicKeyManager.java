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
import com.google.crypto.tink.Util;
import com.google.crypto.tink.proto.EciesAeadDemParams;
import com.google.crypto.tink.proto.EciesAeadHkdfKeyFormat;
import com.google.crypto.tink.proto.EciesAeadHkdfParams;
import com.google.crypto.tink.proto.EciesAeadHkdfPublicKey;
import com.google.crypto.tink.proto.EciesHkdfKemParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.EciesAeadHkdfDemHelper;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridEncrypt;
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
 * This key manager produces new instances of {@code EciesAeadHkdfHybridEncrypt}.
 * It doesn't support key generation.
 */
class EciesAeadHkdfPublicKeyManager implements KeyManager<HybridEncrypt> {
  private static final int VERSION = 0;

  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";

  /** @param serializedKey serialized {@code EciesAeadHkdfPublicKey} proto */
  @Override
  public HybridEncrypt getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      EciesAeadHkdfPublicKey recipientKeyProto = EciesAeadHkdfPublicKey.parseFrom(serializedKey);
      return getPrimitive(recipientKeyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized EciesAeadHkdfPublicKey proto", e);
    }
  }

  /** @param recipientKey {@code EciesAeadHkdfPublicKey} proto */
  @Override
  public HybridEncrypt getPrimitive(MessageLite recipientKey) throws GeneralSecurityException {
    if (!(recipientKey instanceof EciesAeadHkdfPublicKey)) {
      throw new GeneralSecurityException("expected EciesAeadHkdfPublicKey proto");
    }
    EciesAeadHkdfPublicKey recipientKeyProto = (EciesAeadHkdfPublicKey) recipientKey;
    validate(recipientKeyProto);
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

  /**
   * Not supported, please use {@link EciesAeadHkdfPrivateKeyManager}.
   */
  @Override
  public MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    throw new GeneralSecurityException(
        "Not supported, please use the manager of the corresponding private key.");
  }

  /**
   * Not supported, please use {@link EciesAeadHkdfPrivateKeyManager}.
   */
  @Override
  public MessageLite newKey(MessageLite keyFormat) throws GeneralSecurityException {
    throw new GeneralSecurityException(
        "Not supported, please use the manager of the corresponding private key.");
  }

  /**
   * Not supported, please use {@link EciesAeadHkdfPrivateKeyManager}.
   */
  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    throw new GeneralSecurityException(
        "Not supported, please use the manager of the corresponding private key.");
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
   * @param jsonKey JSON formatted {@code EciesAeadHkdfPublicKey}-proto
   * @return {@code EciesAeadHkdfPublicKey}-proto
   */
  @Override
  public MessageLite jsonToKey(final byte[] jsonKey) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKey, Util.UTF_8));
      validateKey(json);
      return EciesAeadHkdfPublicKey.newBuilder()
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
   * @param jsonKeyFormat JSON formatted {@code EciesAeadHkdfPublicKeyFromat}-proto
   * @return {@code EciesAeadHkdfKeyFormat}-proto
   */
  @Override
  public MessageLite jsonToKeyFormat(final byte[] jsonKeyFormat) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKeyFormat, Util.UTF_8));
      validateKeyFormat(json);
      return EciesAeadHkdfKeyFormat.newBuilder()
          .setParams(paramsFromJson(json.getJSONObject("params")))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * Returns a JSON-formatted serialization of the given {@code serializedKey},
   * which must be a {@code EciesAeadHkdfPublicKey}-proto.
   * @throws GeneralSecurityException if the key in {@code serializedKey} is not supported
   */
  @Override
  public byte[] keyToJson(ByteString serializedKey) throws GeneralSecurityException {
    EciesAeadHkdfPublicKey key;
    try {
      key = EciesAeadHkdfPublicKey.parseFrom(serializedKey);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized EciesAeadHkdfPublicKey proto", e);
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
   * which must be a {@code EciesAeadHkdfKeyFormat}-proto.
   * @throws GeneralSecurityException if the format in {@code serializedKeyFromat} is not supported
   */
  @Override
  public byte[] keyFormatToJson(ByteString serializedKeyFormat) throws GeneralSecurityException {
    EciesAeadHkdfKeyFormat format;
    try {
      format = EciesAeadHkdfKeyFormat.parseFrom(serializedKeyFormat);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized EciesAeadHkdfKeyFormat proto", e);
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

  private JSONObject toJson(EciesAeadHkdfParams params)
      throws JSONException, GeneralSecurityException {
    return new JSONObject()
        .put("kemParams", toJson(params.getKemParams()))
        .put("demParams", toJson(params.getDemParams()))
        .put("ecPointFormat", params.getEcPointFormat().toString());
  }

  private JSONObject toJson(EciesHkdfKemParams kemParams) throws JSONException {
    return new JSONObject()
        .put("curveType", kemParams.getCurveType().toString())
        .put("hkdfHashType", kemParams.getHkdfHashType().toString())
        .put("hkdfSalt", Base64.encode(kemParams.getHkdfSalt().toByteArray()));
  }

  private JSONObject toJson(EciesAeadDemParams demParams)
      throws JSONException, GeneralSecurityException {
    return new JSONObject()
        .put("aeadDem", Util.toJson(demParams.getAeadDem()));
  }

  private EciesAeadHkdfParams paramsFromJson(JSONObject json)
      throws JSONException, GeneralSecurityException {
    if (json.length() != 3 || !json.has("kemParams") || !json.has("demParams")
        || !json.has("ecPointFormat")) {
      throw new JSONException("Invalid params.");
    }
    return EciesAeadHkdfParams.newBuilder()
        .setKemParams(kemParamsFromJson(json.getJSONObject("kemParams")))
        .setDemParams(demParamsFromJson(json.getJSONObject("demParams")))
        .setEcPointFormat(Util.getEcPointFormat(json.getString("ecPointFormat")))
        .build();
  }

  private EciesHkdfKemParams kemParamsFromJson(JSONObject json)
      throws JSONException, GeneralSecurityException {
    if (json.length() != 3 || !json.has("curveType") || !json.has("hkdfHashType")
        || !json.has("hkdfSalt")) {
      throw new JSONException("Invalid KEM params.");
    }
    return EciesHkdfKemParams.newBuilder()
        .setCurveType(Util.getEllipticCurveType(json.getString("curveType")))
        .setHkdfHashType(Util.getHashType(json.getString("hkdfHashType")))
        .setHkdfSalt(ByteString.copyFrom(Base64.decode(json.getString("hkdfSalt"))))
        .build();
  }

  private EciesAeadDemParams demParamsFromJson(JSONObject json)
      throws JSONException, GeneralSecurityException {
    if (json.length() != 1 || !json.has("aeadDem")) {
      throw new JSONException("Invalid DEM params.");
    }
    return EciesAeadDemParams.newBuilder()
        .setAeadDem(Util.keyTemplateFromJson(json.getJSONObject("aeadDem")))
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

  private void validate(EciesAeadHkdfKeyFormat format) throws GeneralSecurityException {
    // TODO(przydatek): add more checks.
    HybridUtil.validate(format.getParams());
  }

  private void validate(EciesAeadHkdfPublicKey key) throws GeneralSecurityException {
    // TODO(przydatek): add more checks.
    Validators.validateVersion(key.getVersion(), VERSION);
    HybridUtil.validate(key.getParams());
  }
}
