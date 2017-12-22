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
import com.google.crypto.tink.proto.Ed25519PrivateKey;
import com.google.crypto.tink.proto.Ed25519PublicKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.Ed25519Sign;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * This instance of {@code KeyManager} generates new {@code Ed25519PrivateKey} keys and produces new
 * instances of {@code Ed25519Sign}.
 */
class Ed25519PrivateKeyManager implements PrivateKeyManager<PublicKeySign> {
  /** Type url that this manager supports */
  public static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey";

  /** Current version of this key manager. Keys with greater version are not supported. */
  private static final int VERSION = 0;

  @Override
  public PublicKeySign getPrimitive(ByteString serialized) throws GeneralSecurityException {
    try {
      Ed25519PrivateKey keyProto = Ed25519PrivateKey.parseFrom(serialized);
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid Ed25519 private key", e);
    }
  }

  @Override
  public PublicKeySign getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof Ed25519PrivateKey)) {
      throw new GeneralSecurityException("expected Ed25519PrivateKey proto");
    }
    Ed25519PrivateKey keyProto = (Ed25519PrivateKey) key;
    validate(keyProto);
    return new Ed25519Sign(keyProto.getKeyValue().toByteArray());
  }

  @Override
  public MessageLite newKey(ByteString unused) throws GeneralSecurityException {
    return newKey();
  }

  @Override
  public MessageLite newKey(MessageLite unused) throws GeneralSecurityException {
    return newKey();
  }

  @Override
  public KeyData newKeyData(ByteString unused) throws GeneralSecurityException {
    Ed25519PrivateKey key = newKey();
    return KeyData.newBuilder()
        .setTypeUrl(TYPE_URL)
        .setValue(key.toByteString())
        .setKeyMaterialType(KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE)
        .build();
  }

  @Override
  public KeyData getPublicKeyData(ByteString serializedKey) throws GeneralSecurityException {
    try {
      Ed25519PrivateKey privKeyProto = Ed25519PrivateKey.parseFrom(serializedKey);
      return KeyData.newBuilder()
          .setTypeUrl(Ed25519PublicKeyManager.TYPE_URL)
          .setValue(privKeyProto.getPublicKey().toByteString())
          .setKeyMaterialType(KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC)
          .build();
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized Ed25519PrivateKey proto", e);
    }
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
   * @param jsonKey JSON formatted {@code Ed25519PrivateKey}-proto
   * @return {@code Ed25519PrivateKey}-proto
   */
  @Override
  public MessageLite jsonToKey(final byte[] jsonKey) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKey, Util.UTF_8));
      validateKey(json);
      Ed25519PublicKeyManager publicKeyManager = new Ed25519PublicKeyManager();
      return Ed25519PrivateKey.newBuilder()
          .setVersion(json.getInt("version"))
          .setKeyValue(ByteString.copyFrom(Base64.decode(json.getString("keyValue"))))
          .setPublicKey((Ed25519PublicKey) publicKeyManager.jsonToKey(
              json.getJSONObject("publicKey").toString(4).getBytes(Util.UTF_8)))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * Not supported.
   */
  @Override
  public MessageLite jsonToKeyFormat(final byte[] jsonKeyFormat) throws GeneralSecurityException {
    throw new GeneralSecurityException("Operation not supported.");
  }

  /**
   * Returns a JSON-formatted serialization of the given {@code serializedKey},
   * which must be a {@code Ed25519PrivateKey}-proto.
   * @throws GeneralSecurityException if the key in {@code serializedKey} is not supported
   */
  @Override
  public byte[] keyToJson(ByteString serializedKey) throws GeneralSecurityException {
    Ed25519PrivateKey key;
    try {
      key = Ed25519PrivateKey.parseFrom(serializedKey);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized Ed25519PrivateKey proto", e);
    }
    validate(key);
    Ed25519PublicKeyManager publicKeyManager = new Ed25519PublicKeyManager();
    try {
      return new JSONObject()
          .put("version", key.getVersion())
          .put("keyValue", Base64.encode(key.getKeyValue().toByteArray()))
          .put("publicKey", new JSONObject(new String(
              publicKeyManager.keyToJson(key.getPublicKey().toByteString()), Util.UTF_8)))
          .toString(4).getBytes(Util.UTF_8);
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * Not supported.
   */
  @Override
  public byte[] keyFormatToJson(ByteString serializedKeyFormat) throws GeneralSecurityException {
    throw new GeneralSecurityException("Operation not supported.");
  }

  private void validateKey(JSONObject json) throws JSONException {
    if (json.length() != 3 || !json.has("version") || !json.has("keyValue")
        || !json.has("publicKey")) {
      throw new JSONException("Invalid key.");
    }
  }

  private Ed25519PrivateKey newKey() throws GeneralSecurityException {
    Ed25519Sign.KeyPair keyPair = Ed25519Sign.KeyPair.newKeyPair();
    Ed25519PublicKey publicKey =
        Ed25519PublicKey.newBuilder()
            .setVersion(VERSION)
            .setKeyValue(ByteString.copyFrom(keyPair.getPublicKey()))
            .build();
    return Ed25519PrivateKey.newBuilder()
        .setVersion(VERSION)
        .setKeyValue(ByteString.copyFrom(keyPair.getPrivateKey()))
        .setPublicKey(publicKey)
        .build();
  }

  private void validate(Ed25519PrivateKey keyProto) throws GeneralSecurityException {
    Validators.validateVersion(keyProto.getVersion(), VERSION);
    if (keyProto.getKeyValue().size() != Ed25519Sign.SECRET_KEY_LEN) {
      throw new GeneralSecurityException("invalid Ed25519 private key: incorrect key length");
    }
  }
}
