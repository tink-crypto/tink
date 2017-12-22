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

package com.google.crypto.tink.aead;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.Util;
import com.google.crypto.tink.proto.ChaCha20Poly1305Key;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.ChaCha20Poly1305;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * This instance of {@code KeyManager} generates new {@code ChaCha20Poly1305} keys and produces new
 * instances of {@code ChaCha20Poly1305}.
 */
class ChaCha20Poly1305KeyManager implements KeyManager<Aead> {
  /** Type url that this manager supports */
  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key";

  private static final int KEY_SIZE_IN_BYTES = 32;

  /** Current version of this key manager. Keys with greater version are not supported. */
  private static final int VERSION = 0;

  @Override
  public Aead getPrimitive(ByteString serialized) throws GeneralSecurityException {
    try {
      ChaCha20Poly1305Key keyProto = ChaCha20Poly1305Key.parseFrom(serialized);
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid ChaCha20Poly1305 key", e);
    }
  }

  @Override
  public Aead getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof ChaCha20Poly1305Key)) {
      throw new GeneralSecurityException("expected ChaCha20Poly1305Key proto");
    }
    ChaCha20Poly1305Key keyProto = (ChaCha20Poly1305Key) key;
    validate(keyProto);
    return new ChaCha20Poly1305(keyProto.getKeyValue().toByteArray());
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
    ChaCha20Poly1305Key key = newKey();
    return KeyData.newBuilder()
        .setTypeUrl(TYPE_URL)
        .setValue(key.toByteString())
        .setKeyMaterialType(KeyData.KeyMaterialType.SYMMETRIC)
        .build();
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
   * @param jsonKey JSON formatted {@code ChaCha20Poly1305Key}-proto
   * @return {@code ChaCha20Poly1305Key}-proto
   */
  @Override
  public MessageLite jsonToKey(final byte[] jsonKey) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKey, Util.UTF_8));
      validateKey(json);
      byte[] keyValue = Base64.decode(json.getString("keyValue"));
      return ChaCha20Poly1305Key.newBuilder()
          .setVersion(json.getInt("version"))
          .setKeyValue(ByteString.copyFrom(keyValue))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * Not supported.
   */
  @Override
  public MessageLite jsonToKeyFormat(final byte[] unused) throws GeneralSecurityException {
    throw new GeneralSecurityException("Operation not supported.");
  }

  /**
   * Returns a JSON-formatted serialization of the given {@code serializedKey},
   * which must be a {@code ChaCha20Poly1305Key}-proto.
   * @throws GeneralSecurityException if the key in {@code serializedKey} is not supported
   */
  @Override
  public byte[] keyToJson(ByteString serializedKey) throws GeneralSecurityException {
    ChaCha20Poly1305Key key;
    try {
      key = ChaCha20Poly1305Key.parseFrom(serializedKey);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized ChaCha20Poly1305Key proto", e);
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
  public byte[] keyFormatToJson(ByteString unused) throws GeneralSecurityException {
    throw new GeneralSecurityException("Operation not supported.");
  }

  private void validateKey(JSONObject json) throws JSONException {
    if (json.length() != 2 || !json.has("version") || !json.has("keyValue")) {
      throw new JSONException("Invalid key.");
    }
  }

  private ChaCha20Poly1305Key newKey() throws GeneralSecurityException {
    return ChaCha20Poly1305Key.newBuilder()
        .setVersion(VERSION)
        .setKeyValue(ByteString.copyFrom(Random.randBytes(KEY_SIZE_IN_BYTES)))
        .build();
  }

  private void validate(ChaCha20Poly1305Key keyProto) throws GeneralSecurityException {
    Validators.validateVersion(keyProto.getVersion(), VERSION);
    if (keyProto.getKeyValue().size() != KEY_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("invalid ChaCha20Poly1305Key: incorrect key length");
    }
  }
}
