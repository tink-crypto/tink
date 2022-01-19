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

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.internal.Streams;
import com.google.gson.stream.JsonReader;
import java.io.StringReader;
import java.util.Map;

/**
 * Helper functions to parse JSON strings, and validate strings.
 * */
final class JsonUtil {

  static boolean isValidString(String s) {
    int length = s.length();
    int i = 0;
    while (true) {
      char ch;
      do {
        if (i == length) {
          return true;
        }
        ch = s.charAt(i);
        i++;
      } while (!Character.isSurrogate(ch));
      if (Character.isLowSurrogate(ch) || i == length || !Character.isLowSurrogate(s.charAt(i))) {
        return false;
      }
      i++;
    }
  }

  private static void validateAllStringsInJsonObject(JsonObject jsonObject)
      throws JwtInvalidException {
    for (Map.Entry<String, JsonElement> entry : jsonObject.entrySet()) {
      if (!isValidString(entry.getKey())) {
        throw new JwtInvalidException("JSON string contains character");
      }
      validateAllStringsInJsonElement(entry.getValue());
    }
  }

  private static void validateAllStringsInJsonElement(JsonElement element)
      throws JwtInvalidException {
    if (element.isJsonPrimitive() && element.getAsJsonPrimitive().isString()) {
      if (!isValidString(element.getAsJsonPrimitive().getAsString())) {
        throw new JwtInvalidException("JSON string contains invalid character");
      }
    } else if (element.isJsonObject()) {
      validateAllStringsInJsonObject(element.getAsJsonObject());
    } else if (element.isJsonArray()) {
      validateAllStringsInJsonArray(element.getAsJsonArray());
    }
  }

  private static void validateAllStringsInJsonArray(JsonArray jsonArray)
      throws JwtInvalidException {
    for (JsonElement element : jsonArray) {
      validateAllStringsInJsonElement(element);
    }
  }

  static JsonObject parseJson(String jsonString) throws JwtInvalidException {
    try {
      JsonReader jsonReader = new JsonReader(new StringReader(jsonString));
      jsonReader.setLenient(false);
      JsonObject output = Streams.parse(jsonReader).getAsJsonObject();
      validateAllStringsInJsonObject(output);
      return output;
    } catch (IllegalStateException | JsonParseException | StackOverflowError ex) {
      throw new JwtInvalidException("invalid JSON: " + ex);
    }
  }

  static JsonArray parseJsonArray(String jsonString) throws JwtInvalidException {
    try {
      JsonReader jsonReader = new JsonReader(new StringReader(jsonString));
      jsonReader.setLenient(false);
      JsonArray output = Streams.parse(jsonReader).getAsJsonArray();
      validateAllStringsInJsonArray(output);
      return output;
    } catch (IllegalStateException | JsonParseException | StackOverflowError ex) {
      throw new JwtInvalidException("invalid JSON: " + ex);
    }
  }

  private JsonUtil() {}
}
