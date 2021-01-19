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
import java.security.InvalidAlgorithmParameterException;
import java.util.Iterator;
import java.util.Locale;
import org.json.JSONException;
import org.json.JSONObject;

final class JwtFormat {

  private JwtFormat() {}

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
    JSONObject header = new JSONObject();
    try {
      header.put(JwtNames.HEADER_ALGORITHM, algorithm);
    } catch (JSONException ex) {
      // Should never happen.
      throw new IllegalStateException(ex);
    }
    return Base64.urlSafeEncode(header.toString().getBytes(UTF_8));
  }

  static void validateHeader(String expectedAlgorithm, JSONObject header)
      throws InvalidAlgorithmParameterException, JwtInvalidException {
    validateAlgorithm(expectedAlgorithm);
    try {
      if (!header.has(JwtNames.HEADER_ALGORITHM)) {
        throw new JwtInvalidException("missing algorithm in header");
      }
      Iterator<String> headerIterator = header.keys();
      while (headerIterator.hasNext()) {
        String name = headerIterator.next();
        if (name.equals(JwtNames.HEADER_ALGORITHM)) {
          String algorithm = header.getString(JwtNames.HEADER_ALGORITHM);
          if (!algorithm.equals(expectedAlgorithm)) {
            throw new InvalidAlgorithmParameterException(
                String.format(
                    "invalid algorithm; expected %s, got %s", expectedAlgorithm, algorithm));
          }
        } else if (name.equals(JwtNames.HEADER_TYPE)) {
          String headerType = header.getString(JwtNames.HEADER_TYPE);
          if (!headerType.toUpperCase(Locale.ROOT).equals(JwtNames.HEADER_TYPE_VALUE)) {
            throw new JwtInvalidException(
                String.format(
                    "invalid header type; expected %s, got %s",
                    JwtNames.HEADER_TYPE_VALUE, headerType));
          }
        } else {
          throw new JwtInvalidException(
              String.format("invalid JWT header: unexpected header %s", name));
        }
      }
    } catch (JSONException ex) {
      throw new JwtInvalidException("invalid JWT header: " + ex);
    }
  }

  static JSONObject decodeHeader(String headerStr) throws JwtInvalidException {
    JSONObject json;
    try {
      json = new JSONObject(new String(Base64.urlSafeDecode(headerStr), UTF_8));
    } catch (JSONException | IllegalArgumentException ex) {
      throw new JwtInvalidException("invalid JWT header: " + ex);
    }
    return json;
  }

  static String encodePayload(JSONObject json) {
    return Base64.urlSafeEncode(json.toString().getBytes(UTF_8));
  }

  static JSONObject decodePayload(String payloadStr) throws JwtInvalidException{
    JSONObject json;
    try {
      json = new JSONObject(new String(Base64.urlSafeDecode(payloadStr), UTF_8));
    } catch (JSONException | IllegalArgumentException ex) {
      throw new JwtInvalidException("invalid JWT payload: " + ex);
    }
    return json;
  }

  static String encodeSignature(byte[] signature) {
    return Base64.urlSafeEncode(signature);
  }

  static byte[] decodeSignature(String signatureStr) throws JwtInvalidException {
    try {
      return Base64.urlSafeDecode(signatureStr);
    } catch (IllegalArgumentException ex) {
      throw new JwtInvalidException("invalid JWT signature: " + ex);
    }
  }

  static String createUnsignedCompact(String algorithm, JSONObject payload)
      throws InvalidAlgorithmParameterException {
    return createHeader(algorithm) + "." + encodePayload(payload);
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
