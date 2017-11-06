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
// //////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink;

import com.google.crypto.tink.proto.EcPointFormat;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.KeysetInfo;
import com.google.crypto.tink.proto.OutputPrefixType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import org.json.JSONException;
import org.json.JSONObject;

/** Various helpers. */
public class Util {
  public static final Charset UTF_8 = Charset.forName("UTF-8");

  /** @return a KeysetInfo-proto from a {@code keyset} protobuf. */
  public static KeysetInfo getKeysetInfo(Keyset keyset) {
    KeysetInfo.Builder info = KeysetInfo.newBuilder().setPrimaryKeyId(keyset.getPrimaryKeyId());
    for (Keyset.Key key : keyset.getKeyList()) {
      info.addKeyInfo(getKeyInfo(key));
    }
    return info.build();
  }

  /** @return a KeyInfo-proto from a {@code key} protobuf. */
  public static KeysetInfo.KeyInfo getKeyInfo(Keyset.Key key) {
    return KeysetInfo.KeyInfo.newBuilder()
        .setTypeUrl(key.getKeyData().getTypeUrl())
        .setStatus(key.getStatus())
        .setOutputPrefixType(key.getOutputPrefixType())
        .setKeyId(key.getKeyId())
        .build();
  }

  /**
   * Validates a {@code key}.
   *
   * @throws GeneralSecurityException if {@code key} is invalid.
   */
  public static void validateKey(Keyset.Key key) throws GeneralSecurityException {
    if (!key.hasKeyData()) {
      throw new GeneralSecurityException(String.format("key %d has no key data", key.getKeyId()));
    }

    if (key.getOutputPrefixType() == OutputPrefixType.UNKNOWN_PREFIX) {
      throw new GeneralSecurityException(
          String.format("key %d has unknown prefix", key.getKeyId()));
    }

    if (key.getStatus() == KeyStatusType.UNKNOWN_STATUS) {
      throw new GeneralSecurityException(
          String.format("key %d has unknown status", key.getKeyId()));
    }
  }

  /**
   * Validates a {@code Keyset}.
   *
   * @throws GeneralSecurityException if {@code keyset} is invalid.
   */
  public static void validateKeyset(Keyset keyset) throws GeneralSecurityException {
    if (keyset.getKeyCount() == 0) {
      throw new GeneralSecurityException("empty keyset");
    }

    int primaryKeyId = keyset.getPrimaryKeyId();
    boolean hasPrimaryKey = false;
    boolean containsOnlyPublicKeyMaterial = true;
    for (Keyset.Key key : keyset.getKeyList()) {
      validateKey(key);
      if (key.getStatus() == KeyStatusType.ENABLED && key.getKeyId() == primaryKeyId) {
        if (hasPrimaryKey) {
          throw new GeneralSecurityException("keyset contains multiple primary keys");
        }
        hasPrimaryKey = true;
      }
      if (key.getKeyData().getKeyMaterialType() != KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC) {
        containsOnlyPublicKeyMaterial = false;
      }
      // TODO(thaidn): use TypeLiteral to ensure that all keys are of the same primitive.
    }
    if (!hasPrimaryKey && !containsOnlyPublicKeyMaterial) {
      throw new GeneralSecurityException("keyset doesn't contain a valid primary key");
    }
  }

  /**
   * Reads all bytes from {@code inputStream}.
   */
  public static byte[] readAll(InputStream inputStream) throws IOException {
    ByteArrayOutputStream result = new ByteArrayOutputStream();
    byte[] buf = new byte[1024];
    int count;
    while ((count = inputStream.read(buf)) != -1) {
      result.write(buf, 0, count);
    }
    return result.toByteArray();
  }

  /**
   * Returns a {@code HashType}-enum corresponding to the given string representation.
   */
  public static HashType getHashType(String type) throws GeneralSecurityException {
    String uType = type.toUpperCase();
    if (uType.equals("SHA1")) {
      return HashType.SHA1;
    } else if (uType.equals("SHA224")) {
      return HashType.SHA224;
    } else if (uType.equals("SHA256")) {
      return HashType.SHA256;
    } else if (uType.equals("SHA512")) {
      return HashType.SHA512;
    }
    throw new GeneralSecurityException("unknown hash type: " + type);
  }

  /**
   * Returns a {@code OutputPrefixType}-enum corresponding to the given string representation.
   */
  public static OutputPrefixType getOutputPrefixType(String type) throws GeneralSecurityException {
    String uType = type.toUpperCase();
    if (uType.equals("TINK")) {
      return OutputPrefixType.TINK;
    } else if (uType.equals("LEGACY")) {
      return OutputPrefixType.LEGACY;
    } else if (uType.equals("RAW")) {
      return OutputPrefixType.RAW;
    } else if (uType.equals("CRUNCHY")) {
      return OutputPrefixType.CRUNCHY;
    }
    throw new GeneralSecurityException("unknown output prefix type: " + type);
  }

  /**
   * Returns a {@code EllipticCurveType}-enum corresponding to the given string representation.
   */
  public static EllipticCurveType getEllipticCurveType(String type)
      throws GeneralSecurityException {
    String uType = type.toUpperCase();
    if (uType.equals("NIST_P224")) {
      return EllipticCurveType.NIST_P224;
    } else if (uType.equals("NIST_P256")) {
      return EllipticCurveType.NIST_P256;
    } else if (uType.equals("NIST_P384")) {
      return EllipticCurveType.NIST_P384;
    } else if (uType.equals("NIST_P521")) {
      return EllipticCurveType.NIST_P521;
    }
    throw new GeneralSecurityException("unknown elliptic curve type: " + type);
  }

  /**
   * Returns a {@code EcPointFormat}-enum corresponding to the given string representation.
   */
  public static EcPointFormat getEcPointFormat(String format) throws GeneralSecurityException {
    String uFormat = format.toUpperCase();
    if (uFormat.equals("UNCOMPRESSED")) {
      return EcPointFormat.UNCOMPRESSED;
    } else if (uFormat.equals("COMPRESSED")) {
      return EcPointFormat.COMPRESSED;
    }
    throw new GeneralSecurityException("unknown EC point format: " + format);
  }

  @SuppressWarnings({"rawtypes", "unchecked"})
  public static JSONObject toJson(KeyTemplate keyTemplate)
      throws JSONException, GeneralSecurityException {
    KeyManager keyManager = Registry.getKeyManager(keyTemplate.getTypeUrl());
    return new JSONObject()
        .put("typeUrl", keyTemplate.getTypeUrl())
        .put("value", new JSONObject(new String(
            keyManager.keyFormatToJson(keyTemplate.getValue()), UTF_8)))
        .put("outputPrefixType", keyTemplate.getOutputPrefixType().toString());
  }

  @SuppressWarnings({"rawtypes", "unchecked"})
  public static KeyTemplate keyTemplateFromJson(JSONObject json) throws
      JSONException, GeneralSecurityException {
    if (json.length() != 3 || !json.has("typeUrl") || !json.has("value")
        || !json.has("outputPrefixType")) {
      throw new JSONException("Invalid DEM key template.");
    }
    KeyManager keyManager = Registry.getKeyManager(json.getString("typeUrl"));
    return KeyTemplate.newBuilder()
        .setTypeUrl(json.getString("typeUrl"))
        .setValue(keyManager.jsonToKeyFormat(
            json.getJSONObject("value").toString(4).getBytes(UTF_8)).toByteString())
        .setOutputPrefixType(getOutputPrefixType(json.getString("outputPrefixType")))
        .build();
  }
}
