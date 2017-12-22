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
import com.google.crypto.tink.proto.Ed25519PublicKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.Ed25519Verify;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * This key manager produces new instances of {@code Ed25519Verify}. It doesn't support key
 * generation.
 */
class Ed25519PublicKeyManager implements KeyManager<PublicKeyVerify> {
  /** Type url that this manager supports */
  public static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.Ed25519PublicKey";

  /** Current version of this key manager. Keys with greater version are not supported. */
  private static final int VERSION = 0;

  @Override
  public PublicKeyVerify getPrimitive(ByteString serialized) throws GeneralSecurityException {
    try {
      Ed25519PublicKey keyProto = Ed25519PublicKey.parseFrom(serialized);
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid Ed25519 public key", e);
    }
  }

  @Override
  public PublicKeyVerify getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof Ed25519PublicKey)) {
      throw new GeneralSecurityException("expected Ed25519PublicKey proto");
    }
    Ed25519PublicKey keyProto = (Ed25519PublicKey) key;
    validate(keyProto);
    return new Ed25519Verify(keyProto.getKeyValue().toByteArray());
  }

  /**
   * Not supported, please use {@link Ed25519PrivateKeyManager}.
   */
  @Override
  public MessageLite newKey(ByteString unused) throws GeneralSecurityException {
    throw new GeneralSecurityException(
        "Not supported, please use the manager of the corresponding signing key.");
  }

  /**
   * Not supported, please use {@link Ed25519PrivateKeyManager}.
   */
  @Override
  public MessageLite newKey(MessageLite unused) throws GeneralSecurityException {
    throw new GeneralSecurityException(
        "Not supported, please use the manager of the corresponding signing key.");
  }

  /**
   * Not supported, please use {@link Ed25519PrivateKeyManager}.
   */
  @Override
  public KeyData newKeyData(ByteString unused) throws GeneralSecurityException {
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
   * @param jsonKey JSON formatted {@code Ed25519PublicKey}-proto
   * @return {@code Ed25519PublicKey}-proto
   */
  @Override
  public MessageLite jsonToKey(final byte[] jsonKey) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKey, Util.UTF_8));
      validateKey(json);
      return Ed25519PublicKey.newBuilder()
          .setVersion(json.getInt("version"))
          .setKeyValue(ByteString.copyFrom(Base64.decode(json.getString("keyValue"))))
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
   * which must be a {@code Ed25519PublicKey}-proto.
   * @throws GeneralSecurityException if the key in {@code serializedKey} is not supported
   */
  @Override
  public byte[] keyToJson(ByteString serializedKey) throws GeneralSecurityException {
    Ed25519PublicKey key;
    try {
      key = Ed25519PublicKey.parseFrom(serializedKey);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized Ed25519PublicKey proto", e);
    }
    validate(key);
    try {
      return new JSONObject()
          .put("version", key.getVersion())
          .put("keyValue", Base64.encode(key.getKeyValue().toByteArray()))
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
    if (json.length() != 2 || !json.has("version") || !json.has("keyValue")) {
      throw new JSONException("Invalid key.");
    }
  }

  private void validate(Ed25519PublicKey keyProto) throws GeneralSecurityException {
    Validators.validateVersion(keyProto.getVersion(), VERSION);
    if (keyProto.getKeyValue().size() != Ed25519Verify.PUBLIC_KEY_LEN) {
      throw new GeneralSecurityException("invalid Ed25519 public key: incorrect key length");
    }
  }
}
