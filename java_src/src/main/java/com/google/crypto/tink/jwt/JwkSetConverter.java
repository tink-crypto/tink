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
import com.google.crypto.tink.KeysetWriter;
import com.google.crypto.tink.proto.EncryptedKeyset;
import com.google.crypto.tink.proto.JwtEcdsaPublicKey;
import com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.tinkkey.KeyAccess;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.protobuf.ExtensionRegistryLite;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

/**
 * Provides functions to export a Tink keyset with JWT public keys into a JWK set.
 *
 * It supports the following key types:
 * - JwtEcdsaPublicKey,
 * - RsaSsaPkcs1PublicKey
 * - RsaSsaPssPublicKey (not yet implemented)
 */
public final class JwkSetConverter {

  public static String fromKeysetHandle(KeysetHandle handle, KeyAccess keyAccess)
      throws IOException, GeneralSecurityException {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    handle.writeNoSecret(new JwkSetWriter(outputStream));
    return outputStream.toString();
  }

  private static final class JwkSetWriter implements KeysetWriter {
    private static final String JWT_ECDSA_PUBLIC_KEY_URL =
        "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey";
    private static final String JWT_RSA_SSA_PKCS1_PUBLIC_KEY_URL =
        "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey";
    private static final String JWT_RSA_SSA_PSS_PUBLIC_KEY_URL =
        "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey";

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
        switch (key.getKeyData().getTypeUrl()) {
          case JWT_ECDSA_PUBLIC_KEY_URL:
            keys.add(convertJwtEcdsaKey(key));
            break;
          case JWT_RSA_SSA_PKCS1_PUBLIC_KEY_URL:
            keys.add(convertJwtRsaSsaPkcs1(key));
            break;
          case JWT_RSA_SSA_PSS_PUBLIC_KEY_URL:
            throw new GeneralSecurityException("JwtRsaSsaPssPublicKey is not yet implemented");
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
      if (key.getOutputPrefixType() != OutputPrefixType.RAW) {
        throw new GeneralSecurityException("only OutputPrefixType.RAW is supported");
      }
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
      return jsonKey;
    }

    private static JsonObject convertJwtRsaSsaPkcs1(Keyset.Key key)
        throws IOException, GeneralSecurityException {
      if (key.getOutputPrefixType() != OutputPrefixType.RAW) {
        throw new GeneralSecurityException("only OutputPrefixType.RAW is supported");
      }
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
      return jsonKey;
    }
  }

  private JwkSetConverter() {}
}
