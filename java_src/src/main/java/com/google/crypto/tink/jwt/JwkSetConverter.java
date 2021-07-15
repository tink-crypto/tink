// Copyright 2021 Google LLC
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

package com.google.crypto.tink.jwt;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetManager;
import com.google.crypto.tink.KeysetWriter;
import com.google.crypto.tink.proto.EncryptedKeyset;
import com.google.crypto.tink.proto.JwtEcdsaAlgorithm;
import com.google.crypto.tink.proto.JwtEcdsaPublicKey;
import com.google.crypto.tink.proto.JwtRsaSsaPkcs1Algorithm;
import com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey;
import com.google.crypto.tink.proto.JwtRsaSsaPssAlgorithm;
import com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.KeysetInfo;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.tinkkey.KeyAccess;
import com.google.crypto.tink.tinkkey.KeyHandle;
import com.google.crypto.tink.tinkkey.internal.ProtoKey;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.internal.Streams;
import com.google.gson.stream.JsonReader;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.security.GeneralSecurityException;
import java.util.Optional;

/**
 * Provides functions to import and export Json Web Key (JWK) sets.
 *
 * <p>It currently supports public keys for algorithms ES256, ES384, ES512, RS256, RS384 and RS512.
 */
public final class JwkSetConverter {

  /**
   * Converts a Tink KeysetHandle into a Json Web Key (JWK) set.
   *
   * <p>Currently, only public keys for algorithms ES256, ES384, ES512, RS256, RS384 and RS512 are
   * supported. JWK is defined in https://www.rfc-editor.org/rfc/rfc7517.txt.
   */
  public static String fromKeysetHandle(KeysetHandle handle, KeyAccess keyAccess)
      throws IOException, GeneralSecurityException {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    handle.writeNoSecret(new JwkSetWriter(outputStream));
    return outputStream.toString();
  }

  /**
   * Converts a Json Web Key (JWK) set into a Tink KeysetHandle.
   *
   * <p>It requires that all keys in the set have the "algo" field set. Currently, only public keys
   * for algorithms ES256, ES384, ES512, RS256, RS384 and RS512 are supported. JWK is defined in
   * https://www.rfc-editor.org/rfc/rfc7517.txt.
   */
  public static KeysetHandle toKeysetHandle(String jwkSet, KeyAccess keyAccess)
      throws IOException, GeneralSecurityException {
    JsonObject jsonKeyset;
    try {
      JsonReader jsonReader = new JsonReader(new StringReader(jwkSet));
      jsonReader.setLenient(false);
      jsonKeyset = Streams.parse(jsonReader).getAsJsonObject();
    } catch (IllegalStateException | JsonParseException | StackOverflowError ex) {
      throw new IOException("JWK set is invalid JSON", ex);
    }
    KeysetManager manager = KeysetManager.withEmptyKeyset();
    JsonArray jsonKeys = jsonKeyset.get("keys").getAsJsonArray();
    for (JsonElement element : jsonKeys) {
      JsonObject jsonKey = element.getAsJsonObject();
      String algPrefix = getStringItem(jsonKey, "alg").substring(0, 2);
      KeyData keyData;
      switch (algPrefix) {
        case "RS":
          keyData = convertToRsaSsaPkcs1Key(jsonKey);
          break;
        case "PS":
          keyData = convertToRsaSsaPssKey(jsonKey);
          break;
        case "ES":
          keyData = convertToEcdsaKey(jsonKey);
          break;
        default:
          throw new IOException("unexpected alg value: " + getStringItem(jsonKey, "alg"));
      }
      manager.add(
          KeyHandle.createFromKey(
              new ProtoKey(keyData, com.google.crypto.tink.KeyTemplate.OutputPrefixType.RAW),
              keyAccess));
    }
    KeysetInfo info = manager.getKeysetHandle().getKeysetInfo();
    if (info.getKeyInfoCount() <= 0) {
      throw new IOException("empty keyset");
    }
    manager.setPrimary(info.getKeyInfo(0).getKeyId());
    return manager.getKeysetHandle();
  }

  private static final String JWT_ECDSA_PUBLIC_KEY_URL =
      "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey";
  private static final String JWT_RSA_SSA_PKCS1_PUBLIC_KEY_URL =
      "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey";
  private static final String JWT_RSA_SSA_PSS_PUBLIC_KEY_URL =
      "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey";

  private static final class JwkSetWriter implements KeysetWriter {

    private final OutputStream outputStream;

    private JwkSetWriter(OutputStream outputStream) {
      this.outputStream = outputStream;
    }

    @Override
    public void write(Keyset keyset) throws IOException {
      JsonObject jwkSet;
      try {
        jwkSet = convertKeyset(keyset);
      } catch (GeneralSecurityException exception) {
        throw new IOException(exception);
      }
      outputStream.write(jwkSet.toString().getBytes(UTF_8));
    }

    @Override
    public void write(EncryptedKeyset keyset) {
      throw new UnsupportedOperationException("EncryptedKeyset are not implemented");
    }

    private static JsonObject convertKeyset(Keyset keyset)
        throws IOException, GeneralSecurityException {
      JsonArray keys = new JsonArray();
      for (Keyset.Key key : keyset.getKeyList()) {
        if (key.getStatus() != KeyStatusType.ENABLED) {
          continue;
        }
        if (key.getKeyData().getKeyMaterialType() != KeyMaterialType.ASYMMETRIC_PUBLIC) {
          throw new GeneralSecurityException("only public keys can be converted");
        }
        if ((key.getOutputPrefixType() != OutputPrefixType.RAW)
            && (key.getOutputPrefixType() != OutputPrefixType.TINK)) {
          throw new GeneralSecurityException("only OutputPrefixType RAW and TINK are supported");
        }
        switch (key.getKeyData().getTypeUrl()) {
          case JWT_ECDSA_PUBLIC_KEY_URL:
            keys.add(convertJwtEcdsaKey(key));
            break;
          case JWT_RSA_SSA_PKCS1_PUBLIC_KEY_URL:
            keys.add(convertJwtRsaSsaPkcs1(key));
            break;
          case JWT_RSA_SSA_PSS_PUBLIC_KEY_URL:
            keys.add(convertJwtRsaSsaPss(key));
            break;
          default:
            throw new GeneralSecurityException(
                String.format("key type %s is not supported", key.getKeyData().getTypeUrl()));
        }
      }
      JsonObject jwkSet = new JsonObject();
      jwkSet.add("keys", keys);
      return jwkSet;
    }

    private static JsonObject convertJwtEcdsaKey(Keyset.Key key)
        throws IOException, GeneralSecurityException {
      JwtEcdsaPublicKey jwtEcdsaPublicKey =
          JwtEcdsaPublicKey.parseFrom(
              key.getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
      String alg;
      String crv;
      switch (jwtEcdsaPublicKey.getAlgorithm()) {
        case ES256:
          alg = "ES256";
          crv = "P-256";
          break;
        case ES384:
          alg = "ES384";
          crv = "P-384";
          break;
        case ES512:
          alg = "ES512";
          crv = "P-521";
          break;
        default:
          throw new GeneralSecurityException("unknown algorithm");
      }
      JsonObject jsonKey = new JsonObject();
      jsonKey.addProperty("kty", "EC");
      jsonKey.addProperty("crv", crv);
      jsonKey.addProperty("x", Base64.urlSafeEncode(jwtEcdsaPublicKey.getX().toByteArray()));
      jsonKey.addProperty("y", Base64.urlSafeEncode(jwtEcdsaPublicKey.getY().toByteArray()));
      jsonKey.addProperty("use", "sig");
      jsonKey.addProperty("alg", alg);
      JsonArray keyOps = new JsonArray();
      keyOps.add("verify");
      jsonKey.add("key_ops", keyOps);
      Optional<String> kid = JwtFormat.getKid(key.getKeyId(), key.getOutputPrefixType());
      if (kid.isPresent()) {
        jsonKey.addProperty("kid", kid.get());
      } else if (jwtEcdsaPublicKey.hasCustomKid()) {
        jsonKey.addProperty("kid", jwtEcdsaPublicKey.getCustomKid().getValue());
      }
      return jsonKey;
    }

    private static JsonObject convertJwtRsaSsaPkcs1(Keyset.Key key)
        throws IOException, GeneralSecurityException {
      JwtRsaSsaPkcs1PublicKey jwtRsaSsaPkcs1PublicKey =
          JwtRsaSsaPkcs1PublicKey.parseFrom(
              key.getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
      String alg;
      switch (jwtRsaSsaPkcs1PublicKey.getAlgorithm()) {
        case RS256:
          alg = "RS256";
          break;
        case RS384:
          alg = "RS384";
          break;
        case RS512:
          alg = "RS512";
          break;
        default:
          throw new GeneralSecurityException("unknown algorithm");
      }
      JsonObject jsonKey = new JsonObject();
      jsonKey.addProperty("kty", "RSA");
      jsonKey.addProperty("n", Base64.urlSafeEncode(jwtRsaSsaPkcs1PublicKey.getN().toByteArray()));
      jsonKey.addProperty("e", Base64.urlSafeEncode(jwtRsaSsaPkcs1PublicKey.getE().toByteArray()));
      jsonKey.addProperty("use", "sig");
      jsonKey.addProperty("alg", alg);
      JsonArray keyOps = new JsonArray();
      keyOps.add("verify");
      jsonKey.add("key_ops", keyOps);
      Optional<String> kid = JwtFormat.getKid(key.getKeyId(), key.getOutputPrefixType());
      if (kid.isPresent()) {
        jsonKey.addProperty("kid", kid.get());
      } else if (jwtRsaSsaPkcs1PublicKey.hasCustomKid()) {
        jsonKey.addProperty("kid", jwtRsaSsaPkcs1PublicKey.getCustomKid().getValue());
      }
      return jsonKey;
    }

    private static JsonObject convertJwtRsaSsaPss(Keyset.Key key)
        throws IOException, GeneralSecurityException {
      JwtRsaSsaPssPublicKey jwtRsaSsaPssPublicKey =
          JwtRsaSsaPssPublicKey.parseFrom(
              key.getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
      String alg;
      switch (jwtRsaSsaPssPublicKey.getAlgorithm()) {
        case PS256:
          alg = "PS256";
          break;
        case PS384:
          alg = "PS384";
          break;
        case PS512:
          alg = "PS512";
          break;
        default:
          throw new GeneralSecurityException("unknown algorithm");
      }
      JsonObject jsonKey = new JsonObject();
      jsonKey.addProperty("kty", "RSA");
      jsonKey.addProperty("n", Base64.urlSafeEncode(jwtRsaSsaPssPublicKey.getN().toByteArray()));
      jsonKey.addProperty("e", Base64.urlSafeEncode(jwtRsaSsaPssPublicKey.getE().toByteArray()));
      jsonKey.addProperty("use", "sig");
      jsonKey.addProperty("alg", alg);
      JsonArray keyOps = new JsonArray();
      keyOps.add("verify");
      jsonKey.add("key_ops", keyOps);
      Optional<String> kid = JwtFormat.getKid(key.getKeyId(), key.getOutputPrefixType());
      if (kid.isPresent()) {
        jsonKey.addProperty("kid", kid.get());
      } else if (jwtRsaSsaPssPublicKey.hasCustomKid()) {
        jsonKey.addProperty("kid", jwtRsaSsaPssPublicKey.getCustomKid().getValue());
      }
      return jsonKey;
    }
  }

  private static String getStringItem(JsonObject obj, String name) throws IOException {
    if (!obj.has(name)) {
      throw new IOException(name + " not found");
    }
    if (!obj.get(name).isJsonPrimitive() || !obj.get(name).getAsJsonPrimitive().isString()) {
      throw new IOException(name + " is not a string");
    }
    return obj.get(name).getAsString();
  }

  private static void expectStringItem(JsonObject obj, String name, String expectedValue)
      throws IOException {
    String value = getStringItem(obj, name);
    if (!value.equals(expectedValue)) {
      throw new IOException("unexpected " + name + " value: " + value);
    }
  }

  private static void validateUseIsSig(JsonObject jsonKey) throws IOException {
    if (!jsonKey.has("use")) {
      return;
    }
    expectStringItem(jsonKey, "use", "sig");
  }

  private static void validateKeyOpsIsVerify(JsonObject jsonKey) throws IOException {
    if (!jsonKey.has("key_ops")) {
      return;
    }
    if (!jsonKey.get("key_ops").isJsonArray()) {
      throw new IOException("key_ops is not an array");
    }
    JsonArray keyOps = jsonKey.get("key_ops").getAsJsonArray();
    if (keyOps.size() != 1) {
      throw new IOException("key_ops must contain exactly one element");
    }
    if (!keyOps.get(0).isJsonPrimitive() || !keyOps.get(0).getAsJsonPrimitive().isString()) {
      throw new IOException("key_ops is not a string");
    }
    if (!keyOps.get(0).getAsString().equals("verify")) {
      throw new IOException("unexpected keyOps value: " + keyOps.get(0).getAsString());
    }
  }

  private static KeyData convertToRsaSsaPkcs1Key(JsonObject jsonKey) throws IOException {
    JwtRsaSsaPkcs1Algorithm algorithm;
    switch (getStringItem(jsonKey, "alg")) {
      case "RS256":
        algorithm = JwtRsaSsaPkcs1Algorithm.RS256;
        break;
      case "RS384":
        algorithm = JwtRsaSsaPkcs1Algorithm.RS384;
        break;
      case "RS512":
        algorithm = JwtRsaSsaPkcs1Algorithm.RS512;
        break;
      default:
        throw new IOException("Unknown Rsa Algorithm: " + getStringItem(jsonKey, "alg"));
    }
    if (jsonKey.has("p")
        || jsonKey.has("q")
        || jsonKey.has("dp")
        || jsonKey.has("dq")
        || jsonKey.has("d")
        || jsonKey.has("qi")) {
      throw new UnsupportedOperationException("importing RSA private keys is not implemented");
    }
    expectStringItem(jsonKey, "kty", "RSA");
    validateUseIsSig(jsonKey);
    validateKeyOpsIsVerify(jsonKey);
    JwtRsaSsaPkcs1PublicKey.Builder pkcs1PubKeyBuilder =
        JwtRsaSsaPkcs1PublicKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(algorithm)
            .setE(ByteString.copyFrom(Base64.urlSafeDecode(getStringItem(jsonKey, "e"))))
            .setN(ByteString.copyFrom(Base64.urlSafeDecode(getStringItem(jsonKey, "n"))));
    if (jsonKey.has("kid")) {
      pkcs1PubKeyBuilder.setCustomKid(
          JwtRsaSsaPkcs1PublicKey.CustomKid.newBuilder()
              .setValue(getStringItem(jsonKey, "kid"))
              .build());
    }
    return KeyData.newBuilder()
        .setTypeUrl(JWT_RSA_SSA_PKCS1_PUBLIC_KEY_URL)
        .setValue(pkcs1PubKeyBuilder.build().toByteString())
        .setKeyMaterialType(KeyMaterialType.ASYMMETRIC_PUBLIC)
        .build();
  }

  private static KeyData convertToRsaSsaPssKey(JsonObject jsonKey) throws IOException {
    JwtRsaSsaPssAlgorithm algorithm;
    switch (getStringItem(jsonKey, "alg")) {
      case "PS256":
        algorithm = JwtRsaSsaPssAlgorithm.PS256;
        break;
      case "PS384":
        algorithm = JwtRsaSsaPssAlgorithm.PS384;
        break;
      case "PS512":
        algorithm = JwtRsaSsaPssAlgorithm.PS512;
        break;
      default:
        throw new IOException("Unknown Rsa Algorithm: " + getStringItem(jsonKey, "alg"));
    }
    if (jsonKey.has("p")
        || jsonKey.has("q")
        || jsonKey.has("dq")
        || jsonKey.has("dq")
        || jsonKey.has("d")
        || jsonKey.has("qi")) {
      throw new UnsupportedOperationException("importing RSA private keys is not implemented");
    }
    expectStringItem(jsonKey, "kty", "RSA");
    validateUseIsSig(jsonKey);
    validateKeyOpsIsVerify(jsonKey);
    JwtRsaSsaPssPublicKey.Builder pssPubKeyBuilder =
        JwtRsaSsaPssPublicKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(algorithm)
            .setE(ByteString.copyFrom(Base64.urlSafeDecode(getStringItem(jsonKey, "e"))))
            .setN(ByteString.copyFrom(Base64.urlSafeDecode(getStringItem(jsonKey, "n"))));
    if (jsonKey.has("kid")) {
      pssPubKeyBuilder.setCustomKid(
          JwtRsaSsaPssPublicKey.CustomKid.newBuilder()
              .setValue(getStringItem(jsonKey, "kid"))
              .build());
    }
    return KeyData.newBuilder()
        .setTypeUrl(JWT_RSA_SSA_PSS_PUBLIC_KEY_URL)
        .setValue(pssPubKeyBuilder.build().toByteString())
        .setKeyMaterialType(KeyMaterialType.ASYMMETRIC_PUBLIC)
        .build();
  }

  private static KeyData convertToEcdsaKey(JsonObject jsonKey) throws IOException {
    JwtEcdsaAlgorithm algorithm;
    switch (getStringItem(jsonKey, "alg")) {
      case "ES256":
        expectStringItem(jsonKey, "crv", "P-256");
        algorithm = JwtEcdsaAlgorithm.ES256;
        break;
      case "ES384":
        expectStringItem(jsonKey, "crv", "P-384");
        algorithm = JwtEcdsaAlgorithm.ES384;
        break;
      case "ES512":
        expectStringItem(jsonKey, "crv", "P-521");
        algorithm = JwtEcdsaAlgorithm.ES512;
        break;
      default:
        throw new IOException("Unknown Ecdsa Algorithm: " + getStringItem(jsonKey, "alg"));
    }
    if (jsonKey.has("d")) {
      throw new UnsupportedOperationException("importing ECDSA private keys is not implemented");
    }
    expectStringItem(jsonKey, "kty", "EC");
    validateUseIsSig(jsonKey);
    validateKeyOpsIsVerify(jsonKey);
    JwtEcdsaPublicKey.Builder ecdsaPubKeyBuilder =
        JwtEcdsaPublicKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(algorithm)
            .setX(ByteString.copyFrom(Base64.urlSafeDecode(getStringItem(jsonKey, "x"))))
            .setY(ByteString.copyFrom(Base64.urlSafeDecode(getStringItem(jsonKey, "y"))));
    if (jsonKey.has("kid")) {
      ecdsaPubKeyBuilder.setCustomKid(
          JwtEcdsaPublicKey.CustomKid.newBuilder().setValue(getStringItem(jsonKey, "kid")).build());
    }
    return KeyData.newBuilder()
        .setTypeUrl(JWT_ECDSA_PUBLIC_KEY_URL)
        .setValue(ecdsaPubKeyBuilder.build().toByteString())
        .setKeyMaterialType(KeyMaterialType.ASYMMETRIC_PUBLIC)
        .build();
  }

  private JwkSetConverter() {}
}
