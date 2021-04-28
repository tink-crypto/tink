// Copyright 2020 Google LLC
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

import com.google.crypto.tink.subtle.Base64;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.internal.Streams;
import com.google.gson.stream.JsonReader;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.security.InvalidAlgorithmParameterException;

final class JwtFormat {

  static class Parts {

    String unsignedCompact;
    byte[] signatureOrMac;
    String header;
    String payload;

    Parts(
        String unsignedCompact, byte[] signatureOrMac, String header, String payload) {
      this.unsignedCompact = unsignedCompact;
      this.signatureOrMac = signatureOrMac;
      this.header = header;
      this.payload = payload;
    }
  }

  private JwtFormat() {}

  static JsonObject parseJson(String jsonString) throws JwtInvalidException {
    try {
      JsonReader jsonReader = new JsonReader(new StringReader(jsonString));
      jsonReader.setLenient(false);
      return Streams.parse(jsonReader).getAsJsonObject();
    } catch (IllegalStateException | JsonParseException | StackOverflowError ex) {
      throw new JwtInvalidException("invalid JSON: " + ex);
    }
  }

  static boolean isValidUrlsafeBase64Char(char c) {
    return (((c >= 'a') && (c <= 'z'))
        || ((c >= 'A') && (c <= 'Z'))
        || ((c >= '0') && (c <= '9'))
        || ((c == '-') || (c == '_')));
  }

  // We need this validation, since String(data, UTF_8) ignores invalid characters.
  static void validateUtf8(byte[] data) throws JwtInvalidException {
    CharsetDecoder decoder = UTF_8.newDecoder();
    try {
      decoder.decode(ByteBuffer.wrap(data));
    } catch (CharacterCodingException ex) {
      throw new JwtInvalidException(ex.getMessage());
    }
  }

  static byte[] strictUrlSafeDecode(String encodedData) throws JwtInvalidException {
    for (char c : encodedData.toCharArray()) {
      if (!isValidUrlsafeBase64Char(c)) {
        throw new JwtInvalidException("invalid encoding");
      }
    }
    try {
      return Base64.urlSafeDecode(encodedData);
    } catch (IllegalArgumentException ex) {
      throw new JwtInvalidException("invalid encoding: " + ex);
    }
  }

  private static String validateAlgorithm(String algo) throws InvalidAlgorithmParameterException {
    switch (algo) {
      case "HS256":
      case "HS384":
      case "HS512":
      case "ES256":
      case "ES384":
      case "ES512":
      case "RS256":
      case "RS384":
      case "RS512":
      case "PS256":
      case "PS384":
      case "PS512":
        return algo;
      default:
        throw new InvalidAlgorithmParameterException("invalid algorithm: " + algo);
    }
  }

  static String createHeader(String algorithm) throws InvalidAlgorithmParameterException {
    validateAlgorithm(algorithm);
    JsonObject header = new JsonObject();
    header.addProperty(JwtNames.HEADER_ALGORITHM, algorithm);
    return Base64.urlSafeEncode(header.toString().getBytes(UTF_8));
  }

  static void validateHeader(String expectedAlgorithm, String header)
      throws InvalidAlgorithmParameterException, JwtInvalidException {
    validateAlgorithm(expectedAlgorithm);
    JsonObject parsedHeader = parseJson(header);
    if (!parsedHeader.has(JwtNames.HEADER_ALGORITHM)) {
      throw new JwtInvalidException("missing algorithm in header");
    }
    for (String name : parsedHeader.keySet()) {
      if (name.equals(JwtNames.HEADER_ALGORITHM)) {
        String algorithm = getStringHeader(parsedHeader, JwtNames.HEADER_ALGORITHM);
        if (!algorithm.equals(expectedAlgorithm)) {
          throw new InvalidAlgorithmParameterException(
              String.format(
                  "invalid algorithm; expected %s, got %s", expectedAlgorithm, algorithm));
        }
      } else if (name.equals(JwtNames.HEADER_CRITICAL)) {
        throw new JwtInvalidException(
            "all tokens with crit headers are rejected");
      }
      // Ignore all other headers
    }
  }

  private static String getStringHeader(JsonObject header, String name) throws JwtInvalidException {
    if (!header.has(name)) {
      throw new JwtInvalidException("header " + name + " does not exist");
    }
    if (!header.get(name).isJsonPrimitive() || !header.get(name).getAsJsonPrimitive().isString()) {
      throw new JwtInvalidException("header " + name + " is not a string");
    }
    return header.get(name).getAsString();
  }

  static String decodeHeader(String headerStr) throws JwtInvalidException {
    byte[] data = strictUrlSafeDecode(headerStr);
    validateUtf8(data);
    return new String(data, UTF_8);
  }

  static String encodePayload(String jsonPayload) {
    return Base64.urlSafeEncode(jsonPayload.getBytes(UTF_8));
  }

  static String decodePayload(String payloadStr) throws JwtInvalidException {
    byte[] data = strictUrlSafeDecode(payloadStr);
    validateUtf8(data);
    return new String(data, UTF_8);
  }

  static String encodeSignature(byte[] signature) {
    return Base64.urlSafeEncode(signature);
  }

  static byte[] decodeSignature(String signatureStr) throws JwtInvalidException {
    return strictUrlSafeDecode(signatureStr);
  }

  static Parts splitSignedCompact(String signedCompact) throws JwtInvalidException {
      validateASCII(signedCompact);
      int sigPos = signedCompact.lastIndexOf('.');
      if (sigPos < 0) {
        throw new JwtInvalidException(
            "only tokens in JWS compact serialization format are supported");
      }
      String unsignedCompact = signedCompact.substring(0, sigPos);
      String encodedMac = signedCompact.substring(sigPos + 1);
      byte[] mac = decodeSignature(encodedMac);
      int payloadPos = unsignedCompact.indexOf('.');
      if (payloadPos < 0) {
        throw new JwtInvalidException(
            "only tokens in JWS compact serialization format are supported");
      }
      String encodedHeader = unsignedCompact.substring(0, payloadPos);
      String encodedPayload = unsignedCompact.substring(payloadPos + 1);
      if (encodedPayload.indexOf('.') > 0) {
        throw new JwtInvalidException(
            "only tokens in JWS compact serialization format are supported");
      }
      String header = decodeHeader(encodedHeader);
      String payload = decodePayload(encodedPayload);
      return new Parts(unsignedCompact, mac, header, payload);
  }

  static String createUnsignedCompact(String algorithm, String jsonPayload)
      throws InvalidAlgorithmParameterException {
    return createHeader(algorithm) + "." + encodePayload(jsonPayload);
  }

  static String createSignedCompact(String unsignedCompact, byte[] signature) {
    return unsignedCompact + "." + encodeSignature(signature);
  }

  static void validateASCII(String data) throws JwtInvalidException {
    for (char c : data.toCharArray()) {
      if ((c & 0x80) > 0) {
        throw new JwtInvalidException("Non ascii character");
      }
    }
  }
}
